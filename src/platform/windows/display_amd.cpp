/**
 * @file src/platform/windows/display_amd.cpp
 * @brief Display capture implementation using AMD Direct Capture
 */

extern "C" {
#include <libavcodec/avcodec.h>
#include <libavutil/hwcontext_d3d11va.h>
}

#include "display.h"
#include "misc.h"
#include "src/config.h"
#include "src/main.h"
#include "src/video.h"

#include <AMF/components/DisplayCapture.h>
#include <AMF/components/VideoConverter.h>

namespace platf {
  using namespace std::literals;
}

static void
free_frame(AVFrame *frame) {
  av_frame_free(&frame);
}

using frame_t = util::safe_ptr<AVFrame, free_frame>;

namespace platf::dxgi {
  struct img_amd_t: public platf::img_t {
    // We require the display to keep the AMF library and context
    // around for as long as img_amd_t objects exist.
    std::shared_ptr<platf::display_t> display;

    amf::AMFSurfacePtr surface;
  };

  amf::AMF_SURFACE_FORMAT
  pix_fmt_to_amf_fmt(pix_fmt_e pix_fmt) {
    switch (pix_fmt) {
      case pix_fmt_e::yuv420p:
        return amf::AMF_SURFACE_YUV420P;
      case pix_fmt_e::nv12:
        return amf::AMF_SURFACE_NV12;
      case pix_fmt_e::p010:
        return amf::AMF_SURFACE_P010;
      default:
        BOOST_LOG(error) << "Unsupported pixel format: "sv << (int) pix_fmt;
        return amf::AMF_SURFACE_UNKNOWN;
    }
  }

  class amf_d3d_avcodec_encode_device_t: public avcodec_encode_device_t, public amf::AMFSurfaceObserver {
  public:
    int
    init(std::shared_ptr<platf::display_t> display, pix_fmt_e pix_fmt) {
      this->display = std::static_pointer_cast<display_amd_t>(display);

      // Share the ID3D11Device object with the capture pipeline
      this->data = this->display->device.get();

      // Create the VideoConverter component
      auto result = this->display->amf_factory->CreateComponent(this->display->context, AMFVideoConverter, &converter);
      if (result != AMF_OK) {
        BOOST_LOG(error) << "CreateComponent(VideoConverter) failed: "sv << result;
        return -1;
      }

      converter->SetProperty(AMF_VIDEO_CONVERTER_OUTPUT_FORMAT, pix_fmt_to_amf_fmt(pix_fmt));
      converter->SetProperty(AMF_VIDEO_CONVERTER_COMPUTE_DEVICE, amf::AMF_MEMORY_DX11);
      converter->SetProperty(AMF_VIDEO_CONVERTER_MEMORY_TYPE, amf::AMF_MEMORY_DX11);
      converter->SetProperty(AMF_VIDEO_CONVERTER_SCALE, AMF_VIDEO_CONVERTER_SCALE_BICUBIC);
      converter->SetProperty(AMF_VIDEO_CONVERTER_KEEP_ASPECT_RATIO, true);
      converter->SetProperty(AMF_VIDEO_CONVERTER_FILL, true);
      converter->SetProperty(AMF_VIDEO_CONVERTER_FILL_COLOR, AMFConstructColor(0x00, 0x00, 0x00, 0xFF));

      return 0;
    }

    int
    convert(platf::img_t &img_base) override {
      auto &img = (img_amd_t &) img_base;

      // If the input format changed, (re)initialize the converter
      if (last_input_format != img.surface->GetFormat()) {
        BOOST_LOG(info) << "AMF VideoConverter input format change: "sv << last_input_format << " -> "sv << img.surface->GetFormat();
        display->capture_format = last_input_format = img.surface->GetFormat();

        converter->Terminate();
        auto result = converter->Init(last_input_format, display->resolution.width, display->resolution.height);
        if (result != AMF_OK) {
          BOOST_LOG(error) << "VideoConverter::Init() failed: "sv << result;
          return -1;
        }
      }

      // Submit the RGB frame for YUV conversion
      auto result = converter->SubmitInput(img.surface);
      if (result != AMF_OK) {
        BOOST_LOG(error) << "VideoConverter::SubmitInput() failed: "sv << result;
        return -1;
      }

      // Get the converted output YUV frame. We expect this to block until the output is available.
      amf::AMFSurfacePtr output;
      result = converter->QueryOutput((amf::AMFData **) &output);
      if (result != AMF_OK) {
        BOOST_LOG(error) << "VideoConverter::QueryOutput() failed: "sv << result;
        return -1;
      }

      // Copy the converted frame into our AVFrame-backed surface
      result = output->CopySurfaceRegion(hwframe_surface, 0, 0, 0, 0, hwframe->width, hwframe->height);
      if (result != AMF_OK) {
        BOOST_LOG(error) << "CopySurfaceRegion() failed: "sv << result;
        return -1;
      }

      return 0;
    }

    void
    apply_colorspace() override {
      switch (colorspace.colorspace) {
        case ::video::colorspace_e::rec601:
          converter->SetProperty(AMF_VIDEO_CONVERTER_OUTPUT_COLOR_PRIMARIES, AMF_COLOR_PRIMARIES_SMPTE170M);
          converter->SetProperty(AMF_VIDEO_CONVERTER_OUTPUT_TRANSFER_CHARACTERISTIC, AMF_COLOR_TRANSFER_CHARACTERISTIC_SMPTE170M);
          break;
        case ::video::colorspace_e::rec709:
          converter->SetProperty(AMF_VIDEO_CONVERTER_OUTPUT_COLOR_PRIMARIES, AMF_COLOR_PRIMARIES_BT709);
          converter->SetProperty(AMF_VIDEO_CONVERTER_OUTPUT_TRANSFER_CHARACTERISTIC, AMF_COLOR_TRANSFER_CHARACTERISTIC_BT709);
          break;
        case ::video::colorspace_e::bt2020sdr:
          converter->SetProperty(AMF_VIDEO_CONVERTER_OUTPUT_COLOR_PRIMARIES, AMF_COLOR_PRIMARIES_BT2020);
          converter->SetProperty(AMF_VIDEO_CONVERTER_OUTPUT_TRANSFER_CHARACTERISTIC, AMF_COLOR_TRANSFER_CHARACTERISTIC_BT2020_10);
          break;
        case ::video::colorspace_e::bt2020:
          converter->SetProperty(AMF_VIDEO_CONVERTER_OUTPUT_COLOR_PRIMARIES, AMF_COLOR_PRIMARIES_BT2020);
          converter->SetProperty(AMF_VIDEO_CONVERTER_OUTPUT_TRANSFER_CHARACTERISTIC, AMF_COLOR_TRANSFER_CHARACTERISTIC_SMPTE2084);
          break;
      }

      converter->SetProperty(AMF_VIDEO_CONVERTER_OUTPUT_COLOR_RANGE, colorspace.full_range ? AMF_COLOR_RANGE_FULL : AMF_COLOR_RANGE_STUDIO);
    }

    void
    init_hwframes(AVHWFramesContext *frames) override {
      if (frames->device_ctx->type == AV_HWDEVICE_TYPE_D3D11VA) {
        auto d3d11_frames = (AVD3D11VAFramesContext *) frames->hwctx;

        // The VideoConverter requires shared textures to use CopySurfaceRegion()
        d3d11_frames->MiscFlags = D3D11_RESOURCE_MISC_SHARED;
      }

      // We require a single texture
      frames->initial_pool_size = 1;
    }

    int
    set_frame(AVFrame *frame, AVBufferRef *hw_frames_ctx) override {
      this->hwframe.reset(frame);
      this->frame = frame;

      // Populate this frame with a hardware buffer if one isn't there already
      if (!frame->buf[0]) {
        auto err = av_hwframe_get_buffer(hw_frames_ctx, frame, 0);
        if (err) {
          char err_str[AV_ERROR_MAX_STRING_SIZE] { 0 };
          BOOST_LOG(error) << "Failed to get hwframe buffer: "sv << av_make_error_string(err_str, AV_ERROR_MAX_STRING_SIZE, err);
          return -1;
        }
      }

      // Wrap the frame's ID3D11Texture2D in an AMFSurface object
      auto result = display->context->CreateSurfaceFromDX11Native(frame->data[0], &hwframe_surface, this);
      if (result != AMF_OK) {
        BOOST_LOG(error) << "CreateSurfaceFromDX11Native() failed: "sv << result;
        return -1;
      }

      converter->SetProperty(AMF_VIDEO_CONVERTER_OUTPUT_SIZE, AMFConstructSize(frame->width, frame->height));
      return 0;
    }

    void AMF_STD_CALL
    OnSurfaceDataRelease(amf::AMFSurface *pSurface) override {
      // Nothing
    }

  private:
    std::shared_ptr<display_amd_t> display;
    amf::AMFComponentPtr converter;
    frame_t hwframe;
    amf::AMFSurfacePtr hwframe_surface;
    amf::AMF_SURFACE_FORMAT last_input_format = amf::AMF_SURFACE_UNKNOWN;
  };

  capture_e
  display_amd_t::snapshot(const pull_free_image_cb_t &pull_free_image_cb, std::shared_ptr<platf::img_t> &img_out, std::chrono::milliseconds timeout, bool cursor_visible) {
    // Poll for the next frame
    amf::AMFSurfacePtr output;
    AMF_RESULT result;
    do {
      result = capture->QueryOutput((amf::AMFData **) &output);
    } while (result == AMF_REPEAT);
    if (result != AMF_OK) {
      BOOST_LOG(error) << "DisplayCapture::QueryOutput() failed: "sv << result;
      return capture_e::reinit;
    }

    if (!pull_free_image_cb(img_out)) {
      return capture_e::interrupted;
    }

    auto amd_img = (img_amd_t *) img_out.get();

    // Since AMF doesn't wait for flip, the flip time on the surface isn't accurate
    // to compute the host processing time. We'll just use the time we got the frame.
    amd_img->frame_timestamp = std::chrono::steady_clock::now();

    amd_img->surface = std::move(output);
    return capture_e::ok;
  }

  bool
  test_direct_capture(amf::AMFFactory *amf_factory, adapter_t &adapter, int output_index) {
    D3D_FEATURE_LEVEL featureLevels[] {
      D3D_FEATURE_LEVEL_11_1,
      D3D_FEATURE_LEVEL_11_0,
      D3D_FEATURE_LEVEL_10_1,
      D3D_FEATURE_LEVEL_10_0,
      D3D_FEATURE_LEVEL_9_3,
      D3D_FEATURE_LEVEL_9_2,
      D3D_FEATURE_LEVEL_9_1
    };

    DXGI_ADAPTER_DESC adapter_desc;
    adapter->GetDesc(&adapter_desc);

    // Bail if this is not an AMD GPU
    if (adapter_desc.VendorId != 0x1002) {
      return false;
    }

    device_t device;
    auto status = D3D11CreateDevice(
      adapter.get(),
      D3D_DRIVER_TYPE_UNKNOWN,
      nullptr,
      D3D11_CREATE_DEVICE_FLAGS,
      featureLevels, sizeof(featureLevels) / sizeof(D3D_FEATURE_LEVEL),
      D3D11_SDK_VERSION,
      &device,
      nullptr,
      nullptr);
    if (FAILED(status)) {
      BOOST_LOG(error) << "Failed to create D3D11 device for AMD Direct Capture test [0x"sv << util::hex(status).to_string_view() << ']';
      return false;
    }

    // Initialize the capture context
    amf::AMFContextPtr context;
    auto result = amf_factory->CreateContext(&context);
    if (result != AMF_OK) {
      BOOST_LOG(error) << "CreateContext() failed: "sv << result;
      return false;
    }

    // Associate the context with our ID3D11Device
    result = context->InitDX11(device.get());
    if (result != AMF_OK) {
      BOOST_LOG(error) << "InitDX11() failed: "sv << result;
      return false;
    }

    // Create the DisplayCapture component
    amf::AMFComponentPtr capture;
    result = amf_factory->CreateComponent(context, AMFDisplayCapture, &capture);
    if (result != AMF_OK) {
      BOOST_LOG(error) << "CreateComponent(AMFDisplayCapture) failed: "sv << result;
      return false;
    }

    // Capture the specified output
    capture->SetProperty(AMF_DISPLAYCAPTURE_MONITOR_INDEX, output_index);
    capture->SetProperty(AMF_DISPLAYCAPTURE_MODE, AMF_DISPLAYCAPTURE_MODE_GET_CURRENT_SURFACE);

    // Initialize capture
    result = capture->Init(amf::AMF_SURFACE_UNKNOWN, 0, 0);
    if (result != AMF_OK) {
      BOOST_LOG(error) << "DisplayCapture::Init() failed: "sv << result;
      return false;
    }

    return true;
  }

  bool
  display_amd_t::test_capture(int adapter_index, adapter_t &adapter, int output_index, output_t &output) {
    return test_direct_capture(amf_factory, adapter, output_index);
  }

  int
  display_amd_t::init(const ::video::config_t &config, const std::string &display_name) {
    // We have to load AMF before calling the base init() because we will need it loaded
    // when our test_capture() function is called.
    amfrt_lib.reset(LoadLibraryW(AMF_DLL_NAME));
    if (!amfrt_lib) {
      // Probably not an AMD GPU system
      return -1;
    }

    auto fn_AMFQueryVersion = (AMFQueryVersion_Fn) GetProcAddress((HMODULE) amfrt_lib.get(), AMF_QUERY_VERSION_FUNCTION_NAME);
    auto fn_AMFInit = (AMFInit_Fn) GetProcAddress((HMODULE) amfrt_lib.get(), AMF_INIT_FUNCTION_NAME);

    if (!fn_AMFQueryVersion || !fn_AMFInit) {
      BOOST_LOG(error) << "Missing required AMF function!"sv;
      return -1;
    }

    auto result = fn_AMFQueryVersion(&amf_version);
    if (result != AMF_OK) {
      BOOST_LOG(error) << "AMFQueryVersion() failed: "sv << result;
      return -1;
    }

    // We don't support anything older than AMF 1.4.30. We'll gracefully fall back to DDAPI.
    if (amf_version < AMF_MAKE_FULL_VERSION(1, 4, 30, 0)) {
      BOOST_LOG(warning) << "AMD Direct Capture is not supported on AMF version"sv
                         << AMF_GET_MAJOR_VERSION(amf_version) << '.'
                         << AMF_GET_MINOR_VERSION(amf_version) << '.'
                         << AMF_GET_SUBMINOR_VERSION(amf_version) << '.'
                         << AMF_GET_BUILD_VERSION(amf_version);
      BOOST_LOG(warning) << "Consider updating your AMD graphics driver for better capture performance!"sv;
      return -1;
    }

    // Initialize AMF library
    result = fn_AMFInit(AMF_FULL_VERSION, &amf_factory);
    if (result != AMF_OK) {
      BOOST_LOG(error) << "AMFInit() failed: "sv << result;
      return -1;
    }

    // Initialize the base class
    if (display_base_t::init(config, display_name)) {
      return -1;
    }

    DXGI_ADAPTER_DESC adapter_desc;
    adapter->GetDesc(&adapter_desc);

    // Bail if this is not an AMD GPU
    if (adapter_desc.VendorId != 0x1002) {
      return -1;
    }

    // FIXME: Don't use Direct Capture for a SDR P010 stream. The output is very dim.
    // This seems like a possible bug in VideoConverter when upconverting 8-bit to 10-bit.
    if (config.dynamicRange && !is_hdr()) {
      BOOST_LOG(info) << "AMD Direct Capture is disabled while 10-bit stream is in SDR mode"sv;
      return -1;
    }

    // Create the capture context
    result = amf_factory->CreateContext(&context);
    if (result != AMF_OK) {
      BOOST_LOG(error) << "CreateContext() failed: "sv << result;
      return -1;
    }

    // Associate the context with our ID3D11Device. This will enable multithread protection on the device.
    result = context->InitDX11(device.get());
    if (result != AMF_OK) {
      BOOST_LOG(error) << "InitDX11() failed: "sv << result;
      return -1;
    }

    // Create the DisplayCapture component
    result = amf_factory->CreateComponent(context, AMFDisplayCapture, &capture);
    if (result != AMF_OK) {
      BOOST_LOG(error) << "CreateComponent(AMFDisplayCapture) failed: "sv << result;
      return -1;
    }

    // Set parameters for non-blocking capture
    capture->SetProperty(AMF_DISPLAYCAPTURE_MONITOR_INDEX, output_index);
    capture->SetProperty(AMF_DISPLAYCAPTURE_MODE, AMF_DISPLAYCAPTURE_MODE_GET_CURRENT_SURFACE);

    // Initialize capture
    result = capture->Init(amf::AMF_SURFACE_UNKNOWN, 0, 0);
    if (result != AMF_OK) {
      BOOST_LOG(error) << "DisplayCapture::Init() failed: "sv << result;
      return -1;
    }

    capture->GetProperty(AMF_DISPLAYCAPTURE_FORMAT, &capture_format);
    capture->GetProperty(AMF_DISPLAYCAPTURE_RESOLUTION, &resolution);

    BOOST_LOG(info) << "Desktop resolution ["sv << resolution.width << 'x' << resolution.height << ']';
    BOOST_LOG(info) << "Desktop format ["sv << capture_format << ']';

    // Direct Capture allows fixed rate capture, but the pacing is quite bad. We prefer our own pacing instead.
    self_pacing_capture = false;

    BOOST_LOG(info) << "Using AMD Direct Capture API for display capture"sv;
    return 0;
  }

  std::shared_ptr<platf::img_t>
  display_amd_t::alloc_img() {
    auto img = std::make_shared<img_amd_t>();
    img->display = shared_from_this();
    return img;
  }

  int
  display_amd_t::dummy_img(platf::img_t *img_base) {
    auto img = (img_amd_t *) img_base;

    auto result = context->AllocSurface(amf::AMF_MEMORY_DX11, (amf::AMF_SURFACE_FORMAT) capture_format, resolution.width, resolution.height, &img->surface);
    if (result != AMF_OK) {
      BOOST_LOG(error) << "AllocSurface() failed: "sv << result;
      return -1;
    }

    return 0;
  }

  std::unique_ptr<avcodec_encode_device_t>
  display_amd_t::make_avcodec_encode_device(pix_fmt_e pix_fmt) {
    if (pix_fmt != platf::pix_fmt_e::nv12 && pix_fmt != platf::pix_fmt_e::p010) {
      BOOST_LOG(error) << "display_amd_t doesn't support pixel format ["sv << from_pix_fmt(pix_fmt) << ']';
      return nullptr;
    }

    auto device = std::make_unique<amf_d3d_avcodec_encode_device_t>();
    if (device->init(shared_from_this(), pix_fmt)) {
      return nullptr;
    }

    return device;
  }
}  // namespace platf::dxgi
