/*
 *  Copyright (c) 2026 The WebM project authors. All Rights Reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree. An additional intellectual property rights grant can be found
 *  in the file PATENTS.  All contributing project authors may
 *  be found in the AUTHORS file in the root of the source tree.
 */

/*
 * Structured fuzzer for VP9 encoder SVC + runtime controls.
 *
 * This target intentionally exercises public APIs used by applications
 * integrating libvpx in real-time mode:
 * - vpx_codec_enc_config_default
 * - vpx_codec_enc_init / vpx_codec_enc_config_set
 * - vpx_codec_control with SVC and runtime knobs
 * - vpx_codec_encode / vpx_codec_get_cx_data
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "third_party/nalloc/nalloc.h"
#include "vpx/vp8cx.h"
#include "vpx/vpx_encoder.h"
#include "vpx_ports/mem_ops.h"

#define FUZZ_HDR_SZ 64
#define MAX_FUZZ_FRAMES 96

extern "C" void usage_exit(void) { exit(EXIT_FAILURE); }

static int vpx_img_plane_width(const vpx_image_t *img, int plane) {
  if (plane > 0 && img->x_chroma_shift > 0)
    return (img->d_w + 1) >> img->x_chroma_shift;
  else
    return img->d_w;
}

static int vpx_img_plane_height(const vpx_image_t *img, int plane) {
  if (plane > 0 && img->y_chroma_shift > 0)
    return (img->d_h + 1) >> img->y_chroma_shift;
  else
    return img->d_h;
}

static int fuzz_vpx_img_read(vpx_image_t *img, const uint8_t *data,
                             size_t size) {
  int plane;
  assert(img->bit_depth == 8);
  const size_t bytespp = (img->fmt & VPX_IMG_FMT_HIGHBITDEPTH) ? 2 : 1;

  if (size == 0) return 0;
  size_t used = 0;
  for (plane = 0; plane < 3; ++plane) {
    unsigned char *buf = img->planes[plane];
    const int stride = img->stride[plane];
    int w = vpx_img_plane_width(img, plane);
    const int h = vpx_img_plane_height(img, plane);

    if (img->fmt == VPX_IMG_FMT_NV12 && plane > 1) break;
    if (img->fmt == VPX_IMG_FMT_NV12 && plane == 1) w = (w + 1) & ~1;

    for (int y = 0; y < h; ++y) {
      size_t nb = bytespp * w;
      if (nb > size - used) nb = size - used;
      memcpy(buf, data, nb);
      memset(buf + nb, 0, bytespp * w - nb);
      buf += stride;
      data += nb;
      used += nb;
    }
  }

  return (int)used;
}

static int encode_frame(vpx_codec_ctx_t *codec, vpx_image_t *img,
                        int frame_index, int flags, FILE *out,
                        vpx_enc_deadline_t quality) {
  int got_pkts = 0;
  vpx_codec_iter_t iter = NULL;
  const vpx_codec_cx_pkt_t *pkt = NULL;
  const vpx_codec_err_t res =
      vpx_codec_encode(codec, img, frame_index, 1, flags, quality);
  if (res != VPX_CODEC_OK) return 0;

  while ((pkt = vpx_codec_get_cx_data(codec, &iter)) != NULL) {
    got_pkts = 1;
    if (pkt->kind == VPX_CODEC_CX_FRAME_PKT) {
      (void)fwrite(pkt->data.frame.buf, 1, pkt->data.frame.sz, out);
    }
  }

  return got_pkts;
}

static void fill_default_svc_params(vpx_svc_extra_cfg_t *svc,
                                    const vpx_codec_enc_cfg_t *cfg,
                                    unsigned int temporal_layers) {
  memset(svc, 0, sizeof(*svc));
  for (int i = 0; i < VPX_MAX_LAYERS; ++i) {
    svc->min_quantizers[i] = (int)cfg->rc_min_quantizer;
    svc->max_quantizers[i] = (int)cfg->rc_max_quantizer;
    svc->scaling_factor_num[i] = 1;
    svc->scaling_factor_den[i] = 1;
    svc->speed_per_layer[i] = 6;
    svc->loopfilter_ctrl[i] = -1;
  }

  if (temporal_layers >= 3) {
    svc->temporal_layering_mode = VP9E_TEMPORAL_LAYERING_MODE_0212;
  } else if (temporal_layers == 2) {
    svc->temporal_layering_mode = VP9E_TEMPORAL_LAYERING_MODE_0101;
  } else {
    svc->temporal_layering_mode = VP9E_TEMPORAL_LAYERING_MODE_NOLAYERING;
  }
}

static void apply_vp9_control(vpx_codec_ctx_t *codec, uint8_t op, uint8_t arg,
                              unsigned int temporal_layers) {
  switch (op % 13) {
    case 0:
      vpx_codec_control(codec, VP8E_SET_CPUUSED, (int)(arg % 10));
      break;
    case 1:
      vpx_codec_control(codec, VP9E_SET_TILE_COLUMNS, (int)(arg % 7));
      break;
    case 2:
      vpx_codec_control(codec, VP9E_SET_ROW_MT, (unsigned int)(arg & 1));
      break;
    case 3:
      vpx_codec_control(codec, VP9E_SET_AQ_MODE, (unsigned int)(arg % 4));
      break;
    case 4:
      vpx_codec_control(codec, VP9E_SET_TUNE_CONTENT,
                        (int)(arg % VP9E_CONTENT_INVALID));
      break;
    case 5:
      vpx_codec_control(codec, VP8E_SET_STATIC_THRESHOLD, (unsigned int)arg);
      break;
    case 6:
      vpx_codec_control(codec, VP8E_SET_MAX_INTRA_BITRATE_PCT,
                        (unsigned int)((arg + 1) * 8));
      break;
    case 7:
      vpx_codec_control(codec, VP9E_SET_DISABLE_OVERSHOOT_MAXQ_CBR,
                        (int)(arg & 1));
      break;
    case 8:
      vpx_codec_control(codec, VP9E_SET_DISABLE_LOOPFILTER, (int)(arg % 3));
      break;
    case 9:
      vpx_codec_control(codec, VP9E_SET_COLOR_SPACE, (int)(arg % 8));
      break;
    case 10:
      vpx_codec_control(codec, VP9E_SET_COLOR_RANGE, (int)(arg & 1));
      break;
    case 11:
      vpx_codec_control(codec, VP9E_SET_QUANTIZER_ONE_PASS, (int)(arg % 64));
      break;
    case 12:
      if (temporal_layers > 1) {
        vpx_svc_layer_id_t layer_id;
        memset(&layer_id, 0, sizeof(layer_id));
        layer_id.spatial_layer_id = 0;
        layer_id.temporal_layer_id = (int)(arg % temporal_layers);
        layer_id.temporal_layer_id_per_spatial[0] = layer_id.temporal_layer_id;
        vpx_codec_control(codec, VP9E_SET_SVC_LAYER_ID, &layer_id);
      }
      break;
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size <= FUZZ_HDR_SZ) return 0;
  nalloc_init(NULL);

  vpx_codec_ctx_t codec;
  vpx_image_t raw;
  vpx_codec_enc_cfg_t cfg;
  vpx_svc_extra_cfg_t svc_cfg;
  size_t ctl_len_hint = 0;
  size_t ctl_len = 0;
  const uint8_t *ctl = NULL;
  size_t ctl_size = 0;
  int keyframe_interval = 1;
  int frame_count = 0;
  int reconfigured = 0;
  memset(&codec, 0, sizeof(codec));
  memset(&raw, 0, sizeof(raw));
  memset(&cfg, 0, sizeof(cfg));
  memset(&svc_cfg, 0, sizeof(svc_cfg));

  if (vpx_codec_enc_config_default(vpx_codec_vp9_cx(), &cfg, 0)) return 0;

  static const unsigned int widths[] = { 64, 128, 256, 320, 640, 960 };
  static const unsigned int heights[] = { 48, 72, 144, 180, 360, 540 };
  cfg.g_w = widths[data[0] % (sizeof(widths) / sizeof(widths[0]))];
  cfg.g_h = heights[data[1] % (sizeof(heights) / sizeof(heights[0]))];
  cfg.g_timebase.num = 1;
  cfg.g_timebase.den = 30;
  cfg.g_threads = 1 + (unsigned int)(data[2] % 8);
  cfg.g_lag_in_frames = (unsigned int)(data[3] % 3);
  cfg.rc_target_bitrate = 300 + (unsigned int)(data[4] % 2200);
  cfg.rc_end_usage = (data[5] & 1) ? VPX_CBR : VPX_VBR;
  cfg.kf_mode = VPX_KF_AUTO;
  cfg.kf_min_dist = 0;
  cfg.kf_max_dist = 10 + (unsigned int)(data[6] % 40);
  cfg.g_error_resilient = VPX_ERROR_RESILIENT_DEFAULT;

  const unsigned int temporal_layers = 1 + (unsigned int)(data[7] % 3);
  cfg.ts_number_layers = temporal_layers;
  cfg.ts_periodicity = temporal_layers == 3 ? 4 : (temporal_layers == 2 ? 2 : 1);
  cfg.ts_layer_id[0] = 0;
  cfg.ts_layer_id[1] = temporal_layers == 3 ? 2 : 1;
  cfg.ts_layer_id[2] = temporal_layers == 3 ? 1 : 0;
  cfg.ts_layer_id[3] = temporal_layers == 3 ? 2 : 0;
  cfg.ts_rate_decimator[0] = temporal_layers >= 2 ? 2 : 1;
  cfg.ts_rate_decimator[1] = temporal_layers == 3 ? 2 : 1;
  cfg.ts_rate_decimator[2] = 1;
  cfg.layer_target_bitrate[0] = cfg.rc_target_bitrate / (temporal_layers == 1 ? 1 : 2);
  cfg.layer_target_bitrate[1] = (temporal_layers >= 2)
                                    ? (cfg.rc_target_bitrate * 3) / 4
                                    : cfg.rc_target_bitrate;
  cfg.layer_target_bitrate[2] = cfg.rc_target_bitrate;

  FILE *out = fopen("/dev/null", "wb");
  if (out == NULL) return 0;

  if (vpx_codec_enc_init(&codec, vpx_codec_vp9_cx(), &cfg, 0)) goto fail;

  fill_default_svc_params(&svc_cfg, &cfg, temporal_layers);
  if (temporal_layers > 1) {
    vpx_codec_control(&codec, VP9E_SET_SVC_PARAMETERS, &svc_cfg);
    vpx_codec_control(&codec, VP9E_SET_SVC, 1);
  }

  vpx_codec_control(&codec, VP8E_SET_CPUUSED, (int)(data[8] % 10));
  vpx_codec_control(&codec, VP9E_SET_TILE_COLUMNS, (int)(data[9] % 7));
  vpx_codec_control(&codec, VP9E_SET_ROW_MT, (unsigned int)(data[10] & 1));
  vpx_codec_control(&codec, VP9E_SET_AQ_MODE, (unsigned int)(data[11] % 4));

  if (!vpx_img_alloc(&raw, VPX_IMG_FMT_I420, cfg.g_w, cfg.g_h, 1)) goto fail;

  nalloc_start(data, size);

  data += FUZZ_HDR_SZ;
  size -= FUZZ_HDR_SZ;

  ctl_len_hint = (size_t)((unsigned int)data[-2] << 1);
  ctl_len =
      (ctl_len_hint < size / 2) ? ctl_len_hint : size / 2;
  ctl = data;
  ctl_size = ctl_len;
  data += ctl_size;
  size -= ctl_size;

  keyframe_interval = 1 + (int)(data[-1] % 12);

  while (frame_count < MAX_FUZZ_FRAMES) {
    int flags = 0;
    if (ctl_size >= 2) {
      apply_vp9_control(&codec, ctl[0], ctl[1], temporal_layers);
      ctl += 2;
      ctl_size -= 2;
    }

    const size_t used = (size_t)fuzz_vpx_img_read(&raw, data, size);
    if (used == 0) break;
    data += used;
    size -= used;

    if (frame_count % keyframe_interval == 0) flags |= VPX_EFLAG_FORCE_KF;

    if (!reconfigured && frame_count == 6) {
      vpx_codec_enc_cfg_t new_cfg = cfg;
      new_cfg.rc_target_bitrate += 100;
      new_cfg.rc_dropframe_thresh =
          (new_cfg.rc_dropframe_thresh + 10) % 100;
      if (vpx_codec_enc_config_set(&codec, &new_cfg) == VPX_CODEC_OK) {
        cfg = new_cfg;
        if (temporal_layers > 1) {
          fill_default_svc_params(&svc_cfg, &cfg, temporal_layers);
          vpx_codec_control(&codec, VP9E_SET_SVC_PARAMETERS, &svc_cfg);
          vpx_codec_control(&codec, VP9E_SET_SVC, 1);
        }
      }
      reconfigured = 1;
    }

    (void)encode_frame(&codec, &raw, frame_count, flags, out, VPX_DL_REALTIME);
    ++frame_count;
  }

  while (encode_frame(&codec, NULL, -1, 0, out, VPX_DL_REALTIME)) {
  }

fail:
  nalloc_end();
  vpx_img_free(&raw);
  vpx_codec_destroy(&codec);
  fclose(out);
  return 0;
}
