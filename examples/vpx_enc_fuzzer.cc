/*
 *  Copyright (c) 2025 The WebM project authors. All Rights Reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree. An additional intellectual property rights grant can be found
 *  in the file PATENTS.  All contributing project authors may
 *  be found in the AUTHORS file in the root of the source tree.
 */

/*
 * Fuzzer for libvpx encoders
 * ==========================
 * Requirements
 * --------------
 * Requires Clang 6.0 or above as -fsanitize=fuzzer is used as a linker
 * option.

 * Steps to build
 * --------------
 * Clone libvpx repository
   $git clone https://chromium.googlesource.com/webm/libvpx

 * Create a directory in parallel to libvpx and change directory
   $mkdir vpx_enc_fuzzer
   $cd vpx_enc_fuzzer/

 * Enable sanitizers (Supported: address integer memory thread undefined)
   $source ../libvpx/tools/set_analyzer_env.sh address

 * Configure libvpx.
 * Note --size-limit and VPX_MAX_ALLOCABLE_MEMORY are defined to avoid
 * Out of memory errors when running generated fuzzer binary
   $../libvpx/configure --disable-unit-tests --size-limit=12288x12288 \
   --extra-cflags="-fsanitize=fuzzer-no-link \
   -DVPX_MAX_ALLOCABLE_MEMORY=1073741824" \
   --disable-webm-io --enable-debug --enable-vp8-encoder \
   --enable-vp9-encoder --disable-examples

 * Build libvpx
   $make -j32

 * Build vp9 fuzzer
   $ $CXX $CXXFLAGS -std=gnu++17 -DENCODER=vp9 \
   -fsanitize=fuzzer -I../libvpx -I. -Wl,--start-group \
   ../libvpx/examples/vpx_enc_fuzzer.cc -o ./vpx_enc_fuzzer_vp9 \
   ./libvpx.a -Wl,--end-group

 * ENCODER should be defined as vp9 or vp8 to enable vp9/vp8
 *
 * create a corpus directory and copy some ivf files there.
 * Based on which codec (vp8/vp9) is being tested, it is recommended to
 * have corresponding ivf files in corpus directory
 * Empty corpus directory also is acceptable, though not recommended
   $mkdir CORPUS && cp some-files CORPUS

 * Run fuzzing:
   $./vpx_enc_fuzzer_vp9 CORPUS

 * References:
 * http://llvm.org/docs/LibFuzzer.html
 * https://github.com/google/oss-fuzz
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vpx/vp8cx.h"
#include "vpx/vpx_encoder.h"
#include "vpx_ports/mem_ops.h"
#include "third_party/nalloc/nalloc.h"

// fuzz header to have config options, before raw image data
#define FUZZ_HDR_SZ 32
#define MAX_FUZZ_FRAMES 64

#define VPXC_INTERFACE(name) VPXC_INTERFACE_(name)
#define VPXC_INTERFACE_(name) vpx_codec_##name##_cx()

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
  // TODO: wtc - Need to clamp the sample values so that they are in range
  // For example, if the bit depth is 10, the sample values must be <= 1023.
  assert(img->bit_depth == 8);
  const size_t bytespp = (img->fmt & VPX_IMG_FMT_HIGHBITDEPTH) ? 2 : 1;

  if (size == 0) return 0;
  size_t used = 0;
  for (plane = 0; plane < 3; ++plane) {
    unsigned char *buf = img->planes[plane];
    const int stride = img->stride[plane];
    int w = vpx_img_plane_width(img, plane);
    const int h = vpx_img_plane_height(img, plane);
    int y;

    // Assuming that for nv12 we read all chroma data at once
    if (img->fmt == VPX_IMG_FMT_NV12 && plane > 1) break;
    // Fixing NV12 chroma width if it is odd
    if (img->fmt == VPX_IMG_FMT_NV12 && plane == 1) w = (w + 1) & ~1;

    for (y = 0; y < h; ++y) {
      size_t nb = bytespp * w;
      if (nb > size - used) {
        nb = size - used;
      }
      memcpy(buf, data, nb);
      memset(buf + nb, 0, bytespp * w - nb);
      buf += stride;
      data += nb;
      used += nb;
    }
  }

  return used;
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
      if (fwrite(pkt->data.frame.buf, 1, pkt->data.frame.sz, out) !=
          pkt->data.frame.sz)
        return 0;
    }
  }

  return got_pkts;
}

static void apply_control_op(vpx_codec_ctx_t *codec, uint8_t op, uint8_t arg,
                             int is_vp9) {
  switch (op % 15) {
    case 0: {
      const int cpu_used = is_vp9 ? (int)(arg % 10) : -((int)(arg % 16));
      vpx_codec_control(codec, VP8E_SET_CPUUSED, cpu_used);
      break;
    }
    case 1:
      vpx_codec_control(codec, VP8E_SET_STATIC_THRESHOLD, (unsigned int)arg);
      break;
    case 2:
      vpx_codec_control(codec, VP8E_SET_MAX_INTRA_BITRATE_PCT,
                        (unsigned int)((arg + 1) * 8));
      break;
    case 3:
      if (is_vp9) vpx_codec_control(codec, VP9E_SET_TILE_COLUMNS, (int)(arg % 7));
      break;
    case 4:
      if (is_vp9) vpx_codec_control(codec, VP9E_SET_ROW_MT, (unsigned int)(arg & 1));
      break;
    case 5:
      if (is_vp9) vpx_codec_control(codec, VP9E_SET_AQ_MODE, (unsigned int)(arg % 4));
      break;
    case 6:
      if (is_vp9)
        vpx_codec_control(codec, VP9E_SET_TUNE_CONTENT,
                          (int)(arg % VP9E_CONTENT_INVALID));
      break;
    case 7:
      if (is_vp9) vpx_codec_control(codec, VP9E_SET_SVC, (int)(arg & 1));
      break;
    case 8:
      if (is_vp9)
        vpx_codec_control(codec, VP9E_SET_QUANTIZER_ONE_PASS, (int)(arg % 64));
      break;
    case 9:
      vpx_codec_control(codec, VP8E_SET_TOKEN_PARTITIONS,
                        (int)(arg % (VP8_EIGHT_TOKENPARTITION + 1)));
      break;
    case 10:
      if (is_vp9)
        vpx_codec_control(codec, VP9E_SET_DISABLE_OVERSHOOT_MAXQ_CBR,
                          (int)(arg & 1));
      break;
    case 11:
      if (is_vp9)
        vpx_codec_control(codec, VP9E_SET_DISABLE_LOOPFILTER,
                          (int)(arg % 3));
      break;
    case 12:
      if (!is_vp9)
        vpx_codec_control(codec, VP8E_SET_SCREEN_CONTENT_MODE,
                          (unsigned int)(arg % 3));
      break;
    case 13: {
      int frame_flags = 0;
      if (arg & 1) frame_flags |= VP8_EFLAG_NO_REF_LAST;
      if (arg & 2) frame_flags |= VP8_EFLAG_NO_REF_GF;
      if (arg & 4) frame_flags |= VP8_EFLAG_NO_UPD_LAST;
      if (arg & 8) frame_flags |= VP8_EFLAG_NO_UPD_GF;
      vpx_codec_control(codec, VP8E_SET_FRAME_FLAGS, frame_flags);
      break;
    }
    case 14:
      // do nothing
      break;
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size <= FUZZ_HDR_SZ) {
    return 0;
  }
  nalloc_init(nullptr);

  const int is_vp9 = VPXC_INTERFACE(ENCODER) == vpx_codec_vp9_cx();
  int keyframe_interval = 0;
  int frame_count = 0;
  vpx_codec_ctx_t codec;
  memset(&codec, 0, sizeof(codec));
  vpx_image_t raw;
  memset(&raw, 0, sizeof(raw));
  vpx_codec_enc_cfg_t cfg;
  memset(&cfg, 0, sizeof(cfg));
  vpx_enc_deadline_t quality = VPX_DL_GOOD_QUALITY;
  const uint8_t *control_data = nullptr;
  size_t control_size = 0;
  int reconfig_at;
  int reconfigured = 0;

  if ((data[0] & 0x80) != 0) {
    keyframe_interval = 8;
  }
  if ((data[0] & 0x40) != 0) {
    quality = VPX_DL_REALTIME;
  } else if ((data[0] & 0x20) != 0) {
    quality = VPX_DL_BEST_QUALITY;
  }

  if (vpx_codec_enc_config_default(VPXC_INTERFACE(ENCODER), &cfg, 0)) abort();
  FILE *out = fopen("/dev/null", "wb");

  switch (data[0] & 0x1F) {
    case 0: cfg.g_w = 64; cfg.g_h = 1;
    case 1: cfg.g_w = 1; cfg.g_h = 48;
    case 2: cfg.g_w = 1; cfg.g_h = 1;
    case 3: cfg.g_w = 4; cfg.g_h = 4;
    case 4: cfg.g_w = 16; cfg.g_h = 16;
    default: cfg.g_w = 64; cfg.g_h = 48;
  }
  cfg.g_timebase.num = 1;
  cfg.g_timebase.den = 30;  // fps
  cfg.rc_target_bitrate = 200 + (unsigned int)(data[1]);
  cfg.g_threads = 1 + (unsigned int)(data[2] & 7);
  cfg.g_lag_in_frames = (unsigned int)(data[3] % 3);
  cfg.kf_mode = (data[3] & 1) ? VPX_KF_AUTO : VPX_KF_DISABLED;
  cfg.kf_min_dist = 0;
  cfg.kf_max_dist = cfg.kf_min_dist + 6 + (unsigned int)(data[4] % 32);
  cfg.rc_end_usage = (data[5] & 1) ? VPX_CBR : VPX_VBR;
  cfg.rc_dropframe_thresh = (unsigned int)(data[6] % 50);
  cfg.rc_overshoot_pct = 15 + (unsigned int)(data[7] % 85);
  cfg.rc_undershoot_pct = 15 + (unsigned int)(data[8] % 85);
  cfg.g_error_resilient = 1;

  const size_t control_stream_len = (size_t)((unsigned int)data[9] << 1);
  const size_t bounded_control_len =
      (control_stream_len < (size - FUZZ_HDR_SZ) / 2)
          ? control_stream_len
          : (size - FUZZ_HDR_SZ) / 2;
  reconfig_at = 1 + (data[10] % 12);

  if (vpx_codec_enc_init(&codec, VPXC_INTERFACE(ENCODER), &cfg, 0)) {
    return 0;
  }

  apply_control_op(&codec, data[11], data[12], is_vp9);
  apply_control_op(&codec, data[13], data[14], is_vp9);

  if (!vpx_img_alloc(&raw, VPX_IMG_FMT_I420, cfg.g_w, cfg.g_h, 1)) {
    goto fail;
  }

  nalloc_start(data, size);
  // We may want to add more config options (for more complex encoders as seen
  // in the examples) in the future while still maintaining the same format (so
  // that generated corpus is still valid). So we reserve FUZZ_HDR_SZ=32 bytes
  // for this even if we just use one byte so far.
  data += FUZZ_HDR_SZ;
  size -= FUZZ_HDR_SZ;

  control_data = data;
  control_size = bounded_control_len;
  data += control_size;
  size -= control_size;

  // Encode frames.
  while (frame_count < MAX_FUZZ_FRAMES) {
    int flags = 0;
    if (control_size >= 2) {
      apply_control_op(&codec, control_data[0], control_data[1], is_vp9);
      control_data += 2;
      control_size -= 2;
    }

    size_t size_read = fuzz_vpx_img_read(&raw, data, size);
    if (size_read == 0) break;
    data += size_read;
    size -= size_read;
    if (keyframe_interval > 0 && frame_count % keyframe_interval == 0)
      flags |= VPX_EFLAG_FORCE_KF;

    if (!reconfigured && frame_count == reconfig_at && size >= 2) {
      vpx_codec_enc_cfg_t new_cfg = cfg;
      if (data[0] & 0x80 && cfg.rc_target_bitrate > 1 + (unsigned int)(data[0] & 0x7F)) {
        new_cfg.rc_target_bitrate =
            cfg.rc_target_bitrate - 1 - (unsigned int)(data[0] & 0x7F);
      } else {
        new_cfg.rc_target_bitrate =
            cfg.rc_target_bitrate + 1 + (unsigned int)(data[0]);
      }
      new_cfg.rc_dropframe_thresh =
          (unsigned int)((cfg.rc_dropframe_thresh + data[1]) % 100);
      (void)vpx_codec_enc_config_set(&codec, &new_cfg);
      cfg = new_cfg;
      reconfigured = 1;
      data += 2;
      size -= 2;
    }

    encode_frame(&codec, &raw, frame_count++, flags, out, quality);
  }

  // Flush encoder.
  while (encode_frame(&codec, NULL, -1, 0, out, quality)) {
  }

fail:
  nalloc_end();
  vpx_img_free(&raw);
  vpx_codec_destroy(&codec);
  fclose(out);
  return 0;
}
