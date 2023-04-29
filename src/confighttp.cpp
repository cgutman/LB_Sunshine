// Created by TheElixZammuto on 2021-05-09.
// TODO: Authentication, better handling of routes common to nvhttp, cleanup

#define BOOST_BIND_GLOBAL_PLACEHOLDERS

#include "process.h"

#include <filesystem>
#include <set>

#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>

#include <boost/algorithm/string.hpp>

#include <boost/asio/ssl/context.hpp>

#include <boost/filesystem.hpp>

#include <Simple-Web-Server/crypto.hpp>
#include <Simple-Web-Server/server_https.hpp>
#include <boost/asio/ssl/context_base.hpp>

#include "config.h"
#include "confighttp.h"
#include "crypto.h"
#include "httpcommon.h"
#include "main.h"
#include "network.h"
#include "nvhttp.h"
#include "platform/common.h"
#include "rtsp.h"
#include "utility.h"
#include "uuid.h"
#include "version.h"

using namespace std::literals;

namespace confighttp {
  namespace fs = std::filesystem;
  namespace pt = boost::property_tree;

  using http_server_t = SimpleWeb::Server<SimpleWeb::HTTP>;
  using https_server_t = SimpleWeb::Server<SimpleWeb::HTTPS>;

  using args_t = SimpleWeb::CaseInsensitiveMultimap;
  template <class T>
  using resp_t = std::shared_ptr<typename SimpleWeb::ServerBase<T>::Response>;
  template <class T>
  using req_t = std::shared_ptr<typename SimpleWeb::ServerBase<T>::Request>;

  enum class op_e {
    ADD,
    REMOVE
  };

  template <class T>
  void
  print_req(const req_t<T> &request) {
    BOOST_LOG(debug) << "METHOD :: "sv << request->method;
    BOOST_LOG(debug) << "DESTINATION :: "sv << request->path;

    for (auto &[name, val] : request->header) {
      BOOST_LOG(debug) << name << " -- " << (name == "Authorization" ? "CREDENTIALS REDACTED" : val);
    }

    BOOST_LOG(debug) << " [--] "sv;

    for (auto &[name, val] : request->parse_query_string()) {
      BOOST_LOG(debug) << name << " -- " << val;
    }

    BOOST_LOG(debug) << " [--] "sv;
  }

  template <class T>
  void
  send_unauthorized(resp_t<T> response, req_t<T> request) {
    auto address = request->remote_endpoint().address().to_string();
    BOOST_LOG(info) << "Web UI: ["sv << address << "] -- not authorized"sv;
    const SimpleWeb::CaseInsensitiveMultimap headers {
      { "WWW-Authenticate", R"(Basic realm="Sunshine Gamestream Host", charset="UTF-8")" }
    };
    response->write(SimpleWeb::StatusCode::client_error_unauthorized, headers);
  }

  template <class T>
  void
  send_redirect(resp_t<T> response, req_t<T> request, const char *path) {
    auto address = request->remote_endpoint().address().to_string();
    const SimpleWeb::CaseInsensitiveMultimap headers {
      { "Location", path }
    };
    response->write(SimpleWeb::StatusCode::redirection_temporary_redirect, headers);
  }

  template <class T>
  bool
  authenticate(resp_t<T> response, req_t<T> request) {
    auto address = request->remote_endpoint().address().to_string();
    auto ip_type = net::from_address(address);

    if (ip_type > http::origin_web_ui_allowed) {
      BOOST_LOG(info) << "Web UI: ["sv << address << "] -- denied"sv;
      response->write(SimpleWeb::StatusCode::client_error_forbidden);
      return false;
    }
    else if (request->local_endpoint().port() == map_port(PORT_HTTP) && ip_type != net::net_e::PC) {
      // Redirect all external connections to the HTTP config endpoint to HTTPS
      auto local_address = request->local_endpoint().address().to_string();
      auto new_location = "https://"s + local_address + ':' + std::to_string(map_port(PORT_HTTPS)) + '/';
      BOOST_LOG(info) << "Web UI: ["sv << address << "] -- redirected to "sv << new_location;
      send_redirect<T>(response, request, new_location.c_str());
      return false;
    }

    // If credentials are shown, redirect the user to a /welcome page
    if (config::sunshine.username.empty()) {
      BOOST_LOG(info) << "Web UI: ["sv << address << "] -- not authorized"sv;
      send_redirect<T>(response, request, "/welcome");
      return false;
    }

    auto fg = util::fail_guard([&]() {
      send_unauthorized<T>(response, request);
    });

    auto auth = request->header.find("authorization");
    if (auth == request->header.end()) {
      return false;
    }

    auto &rawAuth = auth->second;
    auto authData = SimpleWeb::Crypto::Base64::decode(rawAuth.substr("Basic "sv.length()));

    int index = authData.find(':');
    if (index >= authData.size() - 1) {
      return false;
    }

    auto username = authData.substr(0, index);
    auto password = authData.substr(index + 1);
    auto hash = util::hex(crypto::hash(password + config::sunshine.salt)).to_string();

    if (username != config::sunshine.username || hash != config::sunshine.password) {
      return false;
    }

    fg.disable();
    return true;
  }

  template <class T>
  void
  not_found(resp_t<T> response, req_t<T> request) {
    pt::ptree tree;
    tree.put("root.<xmlattr>.status_code", 404);

    std::ostringstream data;

    pt::write_xml(data, tree);
    response->write(data.str());

    *response << "HTTP/1.1 404 NOT FOUND\r\n"
              << data.str();
  }

  // todo - combine these functions into a single function that accepts the page, i.e "index", "pin", "apps"
  template <class T>
  void
  getIndexPage(resp_t<T> response, req_t<T> request) {
    if (!authenticate<T>(response, request)) return;

    print_req<T>(request);

    std::string header = read_file(WEB_DIR "header.html");
    std::string content = read_file(WEB_DIR "index.html");
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "text/html; charset=utf-8");
    response->write(header + content, headers);
  }

  template <class T>
  void
  getPinPage(resp_t<T> response, req_t<T> request) {
    if (!authenticate<T>(response, request)) return;

    print_req<T>(request);

    std::string header = read_file(WEB_DIR "header.html");
    std::string content = read_file(WEB_DIR "pin.html");
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "text/html; charset=utf-8");
    response->write(header + content, headers);
  }

  template <class T>
  void
  getAppsPage(resp_t<T> response, req_t<T> request) {
    if (!authenticate<T>(response, request)) return;

    print_req<T>(request);

    std::string header = read_file(WEB_DIR "header.html");
    std::string content = read_file(WEB_DIR "apps.html");
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "text/html; charset=utf-8");
    headers.emplace("Access-Control-Allow-Origin", "https://images.igdb.com/");
    response->write(header + content, headers);
  }

  template <class T>
  void
  getClientsPage(resp_t<T> response, req_t<T> request) {
    if (!authenticate<T>(response, request)) return;

    print_req<T>(request);

    std::string header = read_file(WEB_DIR "header.html");
    std::string content = read_file(WEB_DIR "clients.html");
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "text/html; charset=utf-8");
    response->write(header + content, headers);
  }

  template <class T>
  void
  getConfigPage(resp_t<T> response, req_t<T> request) {
    if (!authenticate<T>(response, request)) return;

    print_req<T>(request);

    std::string header = read_file(WEB_DIR "header.html");
    std::string content = read_file(WEB_DIR "config.html");
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "text/html; charset=utf-8");
    response->write(header + content, headers);
  }

  template <class T>
  void
  getPasswordPage(resp_t<T> response, req_t<T> request) {
    if (!authenticate<T>(response, request)) return;

    print_req<T>(request);

    std::string header = read_file(WEB_DIR "header.html");
    std::string content = read_file(WEB_DIR "password.html");
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "text/html; charset=utf-8");
    response->write(header + content, headers);
  }

  template <class T>
  void
  getWelcomePage(resp_t<T> response, req_t<T> request) {
    print_req<T>(request);
    if (!config::sunshine.username.empty()) {
      send_redirect<T>(response, request, "/");
      return;
    }
    std::string header = read_file(WEB_DIR "header-no-nav.html");
    std::string content = read_file(WEB_DIR "welcome.html");
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "text/html; charset=utf-8");
    response->write(header + content, headers);
  }

  template <class T>
  void
  getTroubleshootingPage(resp_t<T> response, req_t<T> request) {
    if (!authenticate<T>(response, request)) return;

    print_req<T>(request);

    std::string header = read_file(WEB_DIR "header.html");
    std::string content = read_file(WEB_DIR "troubleshooting.html");
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "text/html; charset=utf-8");
    response->write(header + content, headers);
  }

  template <class T>
  void
  getFaviconImage(resp_t<T> response, req_t<T> request) {
    // todo - combine function with getSunshineLogoImage and possibly getNodeModules
    // todo - use mime_types map
    print_req<T>(request);

    std::ifstream in(WEB_DIR "images/favicon.ico", std::ios::binary);
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "image/x-icon");
    response->write(SimpleWeb::StatusCode::success_ok, in, headers);
  }

  template <class T>
  void
  getSunshineLogoImage(resp_t<T> response, req_t<T> request) {
    // todo - combine function with getFaviconImage and possibly getNodeModules
    // todo - use mime_types map
    print_req<T>(request);

    std::ifstream in(WEB_DIR "images/logo-sunshine-45.png", std::ios::binary);
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "image/png");
    response->write(SimpleWeb::StatusCode::success_ok, in, headers);
  }

  bool
  isChildPath(fs::path const &base, fs::path const &query) {
    auto relPath = fs::relative(base, query);
    return *(relPath.begin()) != fs::path("..");
  }

  template <class T>
  void
  getNodeModules(resp_t<T> response, req_t<T> request) {
    print_req<T>(request);
    fs::path webDirPath(WEB_DIR);
    fs::path nodeModulesPath(webDirPath / "node_modules");

    // .relative_path is needed to shed any leading slash that might exist in the request path
    auto filePath = fs::weakly_canonical(webDirPath / fs::path(request->path).relative_path());

    // Don't do anything if file does not exist or is outside the node_modules directory
    if (!isChildPath(filePath, nodeModulesPath)) {
      BOOST_LOG(warning) << "Someone requested a path " << filePath << " that is outside the node_modules folder";
      response->write(SimpleWeb::StatusCode::client_error_bad_request, "Bad Request");
    }
    else if (!fs::exists(filePath)) {
      response->write(SimpleWeb::StatusCode::client_error_not_found);
    }
    else {
      auto relPath = fs::relative(filePath, webDirPath);
      // get the mime type from the file extension mime_types map
      // remove the leading period from the extension
      auto mimeType = mime_types.find(relPath.extension().string().substr(1));
      // check if the extension is in the map at the x position
      if (mimeType != mime_types.end()) {
        // if it is, set the content type to the mime type
        SimpleWeb::CaseInsensitiveMultimap headers;
        headers.emplace("Content-Type", mimeType->second);
        std::ifstream in(filePath.string(), std::ios::binary);
        response->write(SimpleWeb::StatusCode::success_ok, in, headers);
      }
      // do not return any file if the type is not in the map
    }
  }

  template <class T>
  void
  getApps(resp_t<T> response, req_t<T> request) {
    if (!authenticate<T>(response, request)) return;

    print_req<T>(request);

    std::string content = read_file(config::stream.file_apps.c_str());
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "application/json");
    response->write(content, headers);
  }

  template <class T>
  void
  getLogs(resp_t<T> response, req_t<T> request) {
    if (!authenticate<T>(response, request)) return;

    print_req<T>(request);

    std::string content = read_file(config::sunshine.log_file.c_str());
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "text/plain");
    response->write(SimpleWeb::StatusCode::success_ok, content, headers);
  }

  template <class T>
  void
  saveApp(resp_t<T> response, req_t<T> request) {
    if (!authenticate<T>(response, request)) return;

    print_req<T>(request);

    std::stringstream ss;
    ss << request->content.rdbuf();

    pt::ptree outputTree;
    auto g = util::fail_guard([&]() {
      std::ostringstream data;

      pt::write_json(data, outputTree);
      response->write(data.str());
    });

    pt::ptree inputTree, fileTree;

    BOOST_LOG(fatal) << config::stream.file_apps;
    try {
      // TODO: Input Validation
      pt::read_json(ss, inputTree);
      pt::read_json(config::stream.file_apps, fileTree);

      if (inputTree.get_child("prep-cmd").empty()) {
        inputTree.erase("prep-cmd");
      }

      if (inputTree.get_child("detached").empty()) {
        inputTree.erase("detached");
      }

      auto &apps_node = fileTree.get_child("apps"s);
      int index = inputTree.get<int>("index");

      inputTree.erase("index");

      if (index == -1) {
        apps_node.push_back(std::make_pair("", inputTree));
      }
      else {
        // Unfortunately Boost PT does not allow to directly edit the array, copy should do the trick
        pt::ptree newApps;
        int i = 0;
        for (const auto &kv : apps_node) {
          if (i == index) {
            newApps.push_back(std::make_pair("", inputTree));
          }
          else {
            newApps.push_back(std::make_pair("", kv.second));
          }
          i++;
        }
        fileTree.erase("apps");
        fileTree.push_back(std::make_pair("apps", newApps));
      }
      pt::write_json(config::stream.file_apps, fileTree);
    }
    catch (std::exception &e) {
      BOOST_LOG(warning) << "SaveApp: "sv << e.what();

      outputTree.put("status", "false");
      outputTree.put("error", "Invalid Input JSON");
      return;
    }

    outputTree.put("status", "true");
    proc::refresh(config::stream.file_apps);
  }

  template <class T>
  void
  deleteApp(resp_t<T> response, req_t<T> request) {
    if (!authenticate<T>(response, request)) return;

    print_req<T>(request);

    pt::ptree outputTree;
    auto g = util::fail_guard([&]() {
      std::ostringstream data;

      pt::write_json(data, outputTree);
      response->write(data.str());
    });
    pt::ptree fileTree;
    try {
      pt::read_json(config::stream.file_apps, fileTree);
      auto &apps_node = fileTree.get_child("apps"s);
      int index = stoi(request->path_match[1]);

      if (index < 0) {
        outputTree.put("status", "false");
        outputTree.put("error", "Invalid Index");
        return;
      }
      else {
        // Unfortunately Boost PT does not allow to directly edit the array, copy should do the trick
        pt::ptree newApps;
        int i = 0;
        for (const auto &kv : apps_node) {
          if (i++ != index) {
            newApps.push_back(std::make_pair("", kv.second));
          }
        }
        fileTree.erase("apps");
        fileTree.push_back(std::make_pair("apps", newApps));
      }
      pt::write_json(config::stream.file_apps, fileTree);
    }
    catch (std::exception &e) {
      BOOST_LOG(warning) << "DeleteApp: "sv << e.what();
      outputTree.put("status", "false");
      outputTree.put("error", "Invalid File JSON");
      return;
    }

    outputTree.put("status", "true");
    proc::refresh(config::stream.file_apps);
  }

  template <class T>
  void
  uploadCover(resp_t<T> response, req_t<T> request) {
    if (!authenticate<T>(response, request)) return;

    std::stringstream ss;
    std::stringstream configStream;
    ss << request->content.rdbuf();
    pt::ptree outputTree;
    auto g = util::fail_guard([&]() {
      std::ostringstream data;

      SimpleWeb::StatusCode code = SimpleWeb::StatusCode::success_ok;
      if (outputTree.get_child_optional("error").has_value()) {
        code = SimpleWeb::StatusCode::client_error_bad_request;
      }

      pt::write_json(data, outputTree);
      response->write(code, data.str());
    });
    pt::ptree inputTree;
    try {
      pt::read_json(ss, inputTree);
    }
    catch (std::exception &e) {
      BOOST_LOG(warning) << "UploadCover: "sv << e.what();
      outputTree.put("status", "false");
      outputTree.put("error", e.what());
      return;
    }

    auto key = inputTree.get("key", "");
    if (key.empty()) {
      outputTree.put("error", "Cover key is required");
      return;
    }
    auto url = inputTree.get("url", "");

    const std::string coverdir = platf::appdata().string() + "/covers/";
    if (!boost::filesystem::exists(coverdir)) {
      boost::filesystem::create_directories(coverdir);
    }

    std::basic_string path = coverdir + http::url_escape(key) + ".png";
    if (!url.empty()) {
      if (http::url_get_host(url) != "images.igdb.com") {
        outputTree.put("error", "Only images.igdb.com is allowed");
        return;
      }
      if (!http::download_file(url, path)) {
        outputTree.put("error", "Failed to download cover");
        return;
      }
    }
    else {
      auto data = SimpleWeb::Crypto::Base64::decode(inputTree.get<std::string>("data"));

      std::ofstream imgfile(path);
      imgfile.write(data.data(), (int) data.size());
    }
    outputTree.put("path", path);
  }

  template <class T>
  void
  getConfig(resp_t<T> response, req_t<T> request) {
    if (!authenticate<T>(response, request)) return;

    print_req<T>(request);

    pt::ptree outputTree;
    auto g = util::fail_guard([&]() {
      std::ostringstream data;

      pt::write_json(data, outputTree);
      response->write(data.str());
    });

    outputTree.put("status", "true");
    outputTree.put("platform", SUNSHINE_PLATFORM);
    outputTree.put("version", PROJECT_VER);
    outputTree.put("restart_supported", platf::restart_supported());

    auto vars = config::parse_config(read_file(config::sunshine.config_file.c_str()));

    for (auto &[name, value] : vars) {
      outputTree.put(std::move(name), std::move(value));
    }
  }

  template <class T>
  void
  saveConfig(resp_t<T> response, req_t<T> request) {
    if (!authenticate<T>(response, request)) return;

    print_req<T>(request);

    std::stringstream ss;
    std::stringstream configStream;
    ss << request->content.rdbuf();
    pt::ptree outputTree;
    auto g = util::fail_guard([&]() {
      std::ostringstream data;

      pt::write_json(data, outputTree);
      response->write(data.str());
    });
    pt::ptree inputTree;
    try {
      // TODO: Input Validation
      pt::read_json(ss, inputTree);
      for (const auto &kv : inputTree) {
        std::string value = inputTree.get<std::string>(kv.first);
        if (value.length() == 0 || value.compare("null") == 0) continue;

        configStream << kv.first << " = " << value << std::endl;
      }
      write_file(config::sunshine.config_file.c_str(), configStream.str());
    }
    catch (std::exception &e) {
      BOOST_LOG(warning) << "SaveConfig: "sv << e.what();
      outputTree.put("status", "false");
      outputTree.put("error", e.what());
      return;
    }
  }

  template <class T>
  void
  restart(resp_t<T> response, req_t<T> request) {
    if (!authenticate<T>(response, request)) return;

    print_req<T>(request);

    std::stringstream ss;
    std::stringstream configStream;
    ss << request->content.rdbuf();
    pt::ptree outputTree;
    auto g = util::fail_guard([&]() {
      std::ostringstream data;

      pt::write_json(data, outputTree);
      response->write(data.str());
    });

    if (!platf::restart_supported()) {
      outputTree.put("status", false);
      outputTree.put("error", "Restart is not currently supported on this platform");
      return;
    }

    if (!platf::restart()) {
      outputTree.put("status", false);
      outputTree.put("error", "Restart failed");
      return;
    }

    outputTree.put("status", true);
  }

  template <class T>
  void
  savePassword(resp_t<T> response, req_t<T> request) {
    if (!config::sunshine.username.empty() && !authenticate<T>(response, request)) return;

    print_req<T>(request);

    std::stringstream ss;
    std::stringstream configStream;
    ss << request->content.rdbuf();

    pt::ptree inputTree, outputTree;

    auto g = util::fail_guard([&]() {
      std::ostringstream data;
      pt::write_json(data, outputTree);
      response->write(data.str());
    });

    try {
      // TODO: Input Validation
      pt::read_json(ss, inputTree);
      auto username = inputTree.count("currentUsername") > 0 ? inputTree.get<std::string>("currentUsername") : "";
      auto newUsername = inputTree.get<std::string>("newUsername");
      auto password = inputTree.count("currentPassword") > 0 ? inputTree.get<std::string>("currentPassword") : "";
      auto newPassword = inputTree.count("newPassword") > 0 ? inputTree.get<std::string>("newPassword") : "";
      auto confirmPassword = inputTree.count("confirmNewPassword") > 0 ? inputTree.get<std::string>("confirmNewPassword") : "";
      if (newUsername.length() == 0) newUsername = username;
      if (newUsername.length() == 0) {
        outputTree.put("status", false);
        outputTree.put("error", "Invalid Username");
      }
      else {
        auto hash = util::hex(crypto::hash(password + config::sunshine.salt)).to_string();
        if (config::sunshine.username.empty() || (username == config::sunshine.username && hash == config::sunshine.password)) {
          if (newPassword.empty() || newPassword != confirmPassword) {
            outputTree.put("status", false);
            outputTree.put("error", "Password Mismatch");
          }
          else {
            http::save_user_creds(config::sunshine.credentials_file, newUsername, newPassword);
            http::reload_user_creds(config::sunshine.credentials_file);
            outputTree.put("status", true);
          }
        }
        else {
          outputTree.put("status", false);
          outputTree.put("error", "Invalid Current Credentials");
        }
      }
    }
    catch (std::exception &e) {
      BOOST_LOG(warning) << "SavePassword: "sv << e.what();
      outputTree.put("status", false);
      outputTree.put("error", e.what());
      return;
    }
  }

  template <class T>
  void
  savePin(resp_t<T> response, req_t<T> request) {
    if (!authenticate<T>(response, request)) return;

    print_req<T>(request);

    std::stringstream ss;
    ss << request->content.rdbuf();

    pt::ptree inputTree, outputTree;

    auto g = util::fail_guard([&]() {
      std::ostringstream data;
      pt::write_json(data, outputTree);
      response->write(data.str());
    });

    try {
      // TODO: Input Validation
      pt::read_json(ss, inputTree);
      std::string pin = inputTree.get<std::string>("pin");
      outputTree.put("status", nvhttp::pin(pin));
    }
    catch (std::exception &e) {
      BOOST_LOG(warning) << "SavePin: "sv << e.what();
      outputTree.put("status", false);
      outputTree.put("error", e.what());
      return;
    }
  }

  template <class T>
  void
  unpairAll(resp_t<T> response, req_t<T> request) {
    if (!authenticate<T>(response, request)) return;

    print_req<T>(request);

    pt::ptree outputTree;

    auto g = util::fail_guard([&]() {
      std::ostringstream data;
      pt::write_json(data, outputTree);
      response->write(data.str());
    });
    nvhttp::erase_all_clients();
    outputTree.put("status", true);
  }

  template <class T>
  void
  closeApp(resp_t<T> response, req_t<T> request) {
    if (!authenticate<T>(response, request)) return;

    print_req<T>(request);

    pt::ptree outputTree;

    auto g = util::fail_guard([&]() {
      std::ostringstream data;
      pt::write_json(data, outputTree);
      response->write(data.str());
    });

    proc::proc.terminate();
    outputTree.put("status", true);
  }

  template <typename T>
  void
  initialize_server_resources(SimpleWeb::Server<T> &server) {
    server.default_resource["GET"] = not_found<T>;
    server.resource["^/$"]["GET"] = getIndexPage<T>;
    server.resource["^/pin$"]["GET"] = getPinPage<T>;
    server.resource["^/apps$"]["GET"] = getAppsPage<T>;
    server.resource["^/clients$"]["GET"] = getClientsPage<T>;
    server.resource["^/config$"]["GET"] = getConfigPage<T>;
    server.resource["^/password$"]["GET"] = getPasswordPage<T>;
    server.resource["^/welcome$"]["GET"] = getWelcomePage<T>;
    server.resource["^/troubleshooting$"]["GET"] = getTroubleshootingPage<T>;
    server.resource["^/api/pin$"]["POST"] = savePin<T>;
    server.resource["^/api/apps$"]["GET"] = getApps<T>;
    server.resource["^/api/logs$"]["GET"] = getLogs<T>;
    server.resource["^/api/apps$"]["POST"] = saveApp<T>;
    server.resource["^/api/config$"]["GET"] = getConfig<T>;
    server.resource["^/api/config$"]["POST"] = saveConfig<T>;
    server.resource["^/api/restart$"]["POST"] = restart<T>;
    server.resource["^/api/password$"]["POST"] = savePassword<T>;
    server.resource["^/api/apps/([0-9]+)$"]["DELETE"] = deleteApp<T>;
    server.resource["^/api/clients/unpair$"]["POST"] = unpairAll<T>;
    server.resource["^/api/apps/close$"]["POST"] = closeApp<T>;
    server.resource["^/api/covers/upload$"]["POST"] = uploadCover<T>;
    server.resource["^/images/favicon.ico$"]["GET"] = getFaviconImage<T>;
    server.resource["^/images/logo-sunshine-45.png$"]["GET"] = getSunshineLogoImage<T>;
    server.resource["^/node_modules\\/.+$"]["GET"] = getNodeModules<T>;
  }

  void
  start() {
    auto shutdown_event = mail::man->event<bool>(mail::shutdown);

    auto port_https = map_port(PORT_HTTPS);
    https_server_t https_server { config::nvhttp.cert, config::nvhttp.pkey };
    initialize_server_resources<SimpleWeb::HTTPS>(https_server);
    https_server.config.reuse_address = true;
    https_server.config.address = "0.0.0.0"s;
    https_server.config.port = port_https;

    auto port_http = map_port(PORT_HTTP);
    http_server_t http_server;
    initialize_server_resources<SimpleWeb::HTTP>(http_server);
    http_server.config.reuse_address = true;
    http_server.config.address = "0.0.0.0"s;
    http_server.config.port = port_http;

    auto accept_and_run = [&](auto *server) {
      try {
        server->start([](unsigned short port) {
          BOOST_LOG(info) << "Configuration UI available at ["sv << (port == map_port(PORT_HTTPS) ? "https"sv : "http"sv) << "://localhost:"sv << port << "]";
        });
      }
      catch (boost::system::system_error &err) {
        // It's possible the exception gets thrown after calling server->stop() from a different thread
        if (shutdown_event->peek()) {
          return;
        }

        BOOST_LOG(fatal) << "Couldn't start configuration HTTP server on port ["sv << port_https << ", "sv << port_https << "]: "sv << err.what();
        shutdown_event->raise(true);
        return;
      }
    };
    std::thread ssl { accept_and_run, &https_server };
    std::thread tcp { accept_and_run, &http_server };

    // Wait for any event
    shutdown_event->view();

    https_server.stop();
    http_server.stop();

    ssl.join();
    tcp.join();
  }
}  // namespace confighttp
