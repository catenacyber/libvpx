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
 * Structured fuzzer for VP8 multi-resolution + ROI/active-map controls.
 *
 * This target is modeled after multi-resolution and set_maps examples and
 * focuses on public APIs that are not exercised by the basic encoder fuzzer.
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>

#include "third_party/nalloc/nalloc.h"
#include "vpx/vp8cx.h"
#include "vpx/vpx_encoder.h"
#include "vpx_ports/mem_ops.h"

#define FUZZ_HDR_SZ 48
#define NUM_ENCODERS 2
#define MAX_FUZZ_FRAMES 80

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

static void drain_packets(vpx_codec_ctx_t *codec, FILE *out) {
  vpx_codec_iter_t iter = NULL;
  const vpx_codec_cx_pkt_t *pkt = NULL;
  while ((pkt = vpx_codec_get_cx_data(codec, &iter)) != NULL) {
    if (pkt->kind == VPX_CODEC_CX_FRAME_PKT) {
      (void)fwrite(pkt->data.frame.buf, 1, pkt->data.frame.sz, out);
    }
  }
}

static void apply_runtime_controls(vpx_codec_ctx_t *codec, uint8_t op,
                                   uint8_t arg) {
  switch (op % 8) {
    case 0:
      vpx_codec_control(codec, VP8E_SET_CPUUSED, -((int)(arg % 16)));
      break;
    case 1:
      vpx_codec_control(codec, VP8E_SET_STATIC_THRESHOLD, (unsigned int)arg);
      break;
    case 2:
      vpx_codec_control(codec, VP8E_SET_TOKEN_PARTITIONS,
                        (int)(arg % (VP8_EIGHT_TOKENPARTITION + 1)));
      break;
    case 3:
      vpx_codec_control(codec, VP8E_SET_NOISE_SENSITIVITY,
                        (unsigned int)(arg % 5));
      break;
    case 4:
      vpx_codec_control(codec, VP8E_SET_TEMPORAL_LAYER_ID, (int)(arg % 3));
      break;
    case 5: {
      int flags = 0;
      if (arg & 1) flags |= VP8_EFLAG_NO_REF_LAST;
      if (arg & 2) flags |= VP8_EFLAG_NO_REF_GF;
      if (arg & 4) flags |= VP8_EFLAG_NO_UPD_LAST;
      if (arg & 8) flags |= VP8_EFLAG_NO_UPD_GF;
      vpx_codec_control(codec, VP8E_SET_FRAME_FLAGS, flags);
      break;
    }
    case 6:
      vpx_codec_control(codec, VP8E_SET_MAX_INTRA_BITRATE_PCT,
                        (unsigned int)((arg + 1) * 8));
      break;
    case 7:
      vpx_codec_control(codec, VP8E_SET_SCREEN_CONTENT_MODE,
                        (unsigned int)(arg % 3));
      break;
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size <= FUZZ_HDR_SZ) return 0;
  nalloc_init(NULL);

  vpx_codec_ctx_t codec[NUM_ENCODERS];
  vpx_image_t raw;
  vpx_codec_enc_cfg_t cfg[NUM_ENCODERS];
  std::vector<unsigned char> active_maps[NUM_ENCODERS];
  std::vector<unsigned char> roi_maps[NUM_ENCODERS];
  vpx_active_map_t active_cfg[NUM_ENCODERS];
  vpx_roi_map_t roi_cfg[NUM_ENCODERS];
  size_t ctl_len_hint = 0;
  size_t ctl_len = 0;
  const uint8_t *ctl = NULL;
  size_t ctl_size = 0;
  int frame_count = 0;
  int keyframe_interval = 1;
  memset(codec, 0, sizeof(codec));
  memset(&raw, 0, sizeof(raw));
  memset(cfg, 0, sizeof(cfg));
  memset(active_cfg, 0, sizeof(active_cfg));
  memset(roi_cfg, 0, sizeof(roi_cfg));

  if (vpx_codec_enc_config_default(vpx_codec_vp8_cx(), &cfg[0], 0)) return 0;

  static const unsigned int widths[] = { 64, 128, 256, 320, 640 };
  static const unsigned int heights[] = { 48, 72, 144, 180, 360 };
  cfg[0].g_w = widths[data[0] % (sizeof(widths) / sizeof(widths[0]))];
  cfg[0].g_h = heights[data[1] % (sizeof(heights) / sizeof(heights[0]))];
  cfg[0].g_timebase.num = 1;
  cfg[0].g_timebase.den = 30;
  cfg[0].g_threads = 1 + (unsigned int)(data[2] % 4);
  cfg[0].rc_target_bitrate = 300 + (unsigned int)(data[3] % 1600);
  cfg[0].g_lag_in_frames = (unsigned int)(data[4] % 2);
  cfg[0].kf_mode = VPX_KF_AUTO;
  cfg[0].kf_min_dist = 0;
  cfg[0].kf_max_dist = 8 + (unsigned int)(data[5] % 40);

  cfg[1] = cfg[0];
  cfg[1].rc_target_bitrate = cfg[0].rc_target_bitrate / 2 + 1;
  cfg[1].g_w = (cfg[0].g_w + 1) / 2;
  cfg[1].g_h = (cfg[0].g_h + 1) / 2;
  if (cfg[1].g_w & 1) cfg[1].g_w++;
  if (cfg[1].g_h & 1) cfg[1].g_h++;

  const vpx_rational_t dsf[NUM_ENCODERS] = { { 2, 1 }, { 1, 1 } };

  FILE *out = fopen("/dev/null", "wb");
  if (out == NULL) return 0;

  if (vpx_codec_enc_init_multi(&codec[0], vpx_codec_vp8_cx(), &cfg[0],
                               NUM_ENCODERS, 0, &dsf[0])) {
    goto fail;
  }

  if (!vpx_img_alloc(&raw, VPX_IMG_FMT_I420, cfg[0].g_w, cfg[0].g_h, 1)) {
    goto fail;
  }

  for (int i = 0; i < NUM_ENCODERS; ++i) {
    const unsigned int rows = (cfg[i].g_h + 15) / 16;
    const unsigned int cols = (cfg[i].g_w + 15) / 16;
    active_maps[i].resize((size_t)rows * cols, 1);
    roi_maps[i].resize((size_t)rows * cols, 0);

    active_cfg[i].rows = rows;
    active_cfg[i].cols = cols;
    active_cfg[i].active_map = active_maps[i].data();

    roi_cfg[i].enabled = 1;
    roi_cfg[i].rows = rows;
    roi_cfg[i].cols = cols;
    roi_cfg[i].roi_map = roi_maps[i].data();
    for (int seg = 0; seg < 8; ++seg) {
      roi_cfg[i].delta_q[seg] = 0;
      roi_cfg[i].delta_lf[seg] = 0;
      roi_cfg[i].skip[seg] = 0;
      roi_cfg[i].ref_frame[seg] = -1;
    }

    vpx_codec_control(&codec[i], VP8E_SET_ACTIVEMAP, &active_cfg[i]);
    vpx_codec_control(&codec[i], VP8E_SET_ROI_MAP, &roi_cfg[i]);
  }

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

  keyframe_interval = 1 + (int)(data[-1] % 10);

  while (frame_count < MAX_FUZZ_FRAMES) {
    const size_t used = (size_t)fuzz_vpx_img_read(&raw, data, size);
    if (used == 0) break;
    data += used;
    size -= used;

    for (int i = 0; i < NUM_ENCODERS; ++i) {
      if (ctl_size >= 2) {
        apply_runtime_controls(&codec[i], ctl[0], ctl[1]);
        ctl += 2;
        ctl_size -= 2;
      }

      if (!active_maps[i].empty()) {
        const size_t idx = (size_t)(frame_count % active_maps[i].size());
        active_maps[i][idx] = (unsigned char)((frame_count + i) & 1);
        roi_maps[i][idx] = (unsigned char)((frame_count + i) % 4);
      }

      vpx_codec_control(&codec[i], VP8E_SET_ACTIVEMAP, &active_cfg[i]);
      vpx_codec_control(&codec[i], VP8E_SET_ROI_MAP, &roi_cfg[i]);
    }

    int flags = 0;
    if (frame_count % keyframe_interval == 0) flags |= VPX_EFLAG_FORCE_KF;

    if (vpx_codec_encode(&codec[0], &raw, frame_count, 1, flags,
                         VPX_DL_REALTIME) != VPX_CODEC_OK) {
      break;
    }

    for (int i = 0; i < NUM_ENCODERS; ++i) {
      drain_packets(&codec[i], out);
    }

    ++frame_count;
  }

  while (vpx_codec_encode(&codec[0], NULL, -1, 1, 0, VPX_DL_REALTIME) ==
         VPX_CODEC_OK) {
    int got = 0;
    for (int i = 0; i < NUM_ENCODERS; ++i) {
      vpx_codec_iter_t iter = NULL;
      const vpx_codec_cx_pkt_t *pkt = NULL;
      while ((pkt = vpx_codec_get_cx_data(&codec[i], &iter)) != NULL) {
        got = 1;
        if (pkt->kind == VPX_CODEC_CX_FRAME_PKT) {
          (void)fwrite(pkt->data.frame.buf, 1, pkt->data.frame.sz, out);
        }
      }
    }
    if (!got) break;
  }

fail:
  nalloc_end();
  vpx_img_free(&raw);
  for (int i = 0; i < NUM_ENCODERS; ++i) {
    vpx_codec_destroy(&codec[i]);
  }
  fclose(out);
  return 0;
}
