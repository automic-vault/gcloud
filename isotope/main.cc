#include <Python.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <xpc/xpc.h>
#include <mach-o/dyld.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <unistd.h>
#include <filesystem>
#include <string>
#include <vector>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>

namespace fs = std::filesystem;
static std::vector<std::string> arguments;
static std::string target, original_cwd;
static const char *identity = "anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = ZU76A67LGU and identifier \"com.automicvault.gcloud\"";

static PyObject *fail(const char *message) { PyErr_SetString(PyExc_RuntimeError, message); return nullptr; }
static bool valid_utf8(const std::string &value) {
  CFStringRef s = CFStringCreateWithBytes(nullptr, (const UInt8 *)value.data(), value.size(), kCFStringEncodingUTF8, false);
  if (!s) return false;
  CFRelease(s); return true;
}
static bool text(PyObject *object, std::string &value) {
  if (!PyUnicode_Check(object)) return false;
  Py_ssize_t length;
  const char *p = PyUnicode_AsUTF8AndSize(object, &length);
  if (!p || length > 1024 * 1024 || memchr(p, 0, length)) return false;
  value.assign(p, length); return true;
}
static PyObject *request(PyObject *, PyObject *args) {
  PyObject *op_arg, *key_arg, *value_arg = Py_None, *expected_arg = Py_None, *context_arg = Py_None;
  if (!PyArg_ParseTuple(args, "OO|OOO", &op_arg, &key_arg, &value_arg, &expected_arg, &context_arg)) return nullptr;
  std::string op, key, value, expected, context;
  if (!text(op_arg, op) || !text(key_arg, key) ||
      (op != "keys" && op != "gcloud-save" && op != "gcloud-delete") ||
      key.rfind("GCLOUD_AUTH_", 0) != 0 || key.size() <= 12 || key.size() > 492 ||
      (key.size() - 12) % 2 || key.find_first_not_of("0123456789ABCDEF", 12) != std::string::npos)
    return fail("Invalid gcloud custody request");
  if (op == "gcloud-save" && !text(value_arg, value)) return fail("Invalid gcloud credential");
  if (expected_arg != Py_None && !text(expected_arg, expected)) return fail("Invalid prior credential");
  if (!text(context_arg, context) || context.size() > 8192) return fail("Invalid gcloud operation context");
  xpc_object_t message = xpc_dictionary_create_empty();
  xpc_dictionary_set_string(message, "op", op.c_str());
  xpc_dictionary_set_string(message, "key", key.c_str());
  xpc_dictionary_set_string(message, "cwd", original_cwd.c_str());
  xpc_dictionary_set_string(message, "gcloud_context", context.c_str());
  if (op == "gcloud-save") xpc_dictionary_set_string(message, "value", value.c_str());
  if (op != "keys") {
    xpc_dictionary_set_bool(message, "expected_present", expected_arg != Py_None);
    if (expected_arg != Py_None) xpc_dictionary_set_string(message, "expected_value", expected.c_str());
  }
  xpc_dictionary_set_string(message, "target", target.c_str());
  xpc_dictionary_set_string(message, "tool", "gcloud");
  xpc_object_t argv = xpc_array_create_empty();
  for (const auto &arg : arguments) xpc_array_set_string(argv, XPC_ARRAY_APPEND, arg.c_str());
  xpc_dictionary_set_value(message, "args", argv); xpc_release(argv);
  if (op == "keys") {
    xpc_dictionary_set_string(message, "title", "gcloud credential requested");
    xpc_dictionary_set_string(message, "detail", ("gcloud needs its user OAuth credential. Resolved context: " + context).c_str());
    xpc_dictionary_set_bool(message, "replace_existing_env", true);
    xpc_dictionary_set_bool(message, "allow_missing_keys", false);
    xpc_object_t keys = xpc_array_create_empty();
    xpc_array_set_string(keys, XPC_ARRAY_APPEND, key.c_str());
    xpc_dictionary_set_value(message, "keys", keys); xpc_release(keys);
    xpc_object_t conflicts = xpc_array_create_empty();
    xpc_dictionary_set_value(message, "env_conflicts", conflicts); xpc_release(conflicts);
  }
  xpc_connection_t connection = xpc_connection_create_mach_service("com.automicvault.av2.approval", nullptr, 0);
  const char *server = "anchor apple generic and certificate leaf[subject.OU] = ZU76A67LGU and identifier \"com.automicvault\"";
  if (!connection || xpc_connection_set_peer_code_signing_requirement(connection, server) != 0) {
    if (connection) xpc_release(connection);
    xpc_release(message); return fail("Cannot authenticate Automic Vault");
  }
  xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
    if (xpc_get_type(event) == XPC_TYPE_DICTIONARY) {
      const char *name = xpc_dictionary_get_string(event, "event");
      if (name && strcmp(name, "human-approval-required") == 0) fputs("Automic Vault: human Approval required\n", stderr);
    }
  });
  xpc_connection_activate(connection);
  xpc_object_t reply;
  Py_BEGIN_ALLOW_THREADS
  reply = xpc_connection_send_message_with_reply_sync(connection, message);
  Py_END_ALLOW_THREADS
  xpc_release(message); xpc_connection_cancel(connection); xpc_release(connection);
  if (!reply || xpc_get_type(reply) != XPC_TYPE_DICTIONARY) {
    if (reply) xpc_release(reply);
    return fail("Automic Vault is unavailable");
  }
  auto ok = xpc_dictionary_get_value(reply, "ok");
  if (!ok || xpc_get_type(ok) != XPC_TYPE_BOOL) { xpc_release(reply); return fail("Invalid Automic Vault reply"); }
  if (!xpc_bool_get_value(ok)) {
    const char *error = xpc_dictionary_get_string(reply, "error");
    std::string reason = error ? error : "Automic Vault denied the request";
    xpc_release(reply);
    if (op == "keys" && reason == "failed to load secret " + key + ": -25300") Py_RETURN_NONE;
    return fail(reason.c_str());
  }
  if (op != "keys") { xpc_release(reply); Py_RETURN_NONE; }
  auto secrets = xpc_dictionary_get_value(reply, "secrets");
  const char *secret = secrets && xpc_get_type(secrets) == XPC_TYPE_DICTIONARY ? xpc_dictionary_get_string(secrets, key.c_str()) : nullptr;
  if (!secret || strlen(secret) > 1024 * 1024) { xpc_release(reply); return fail("Invalid credential reply"); }
  PyObject *result = PyUnicode_FromString(secret);
  xpc_release(reply); return result;
}
static PyMethodDef methods[] = {{"request", request, METH_VARARGS, nullptr}, {nullptr, nullptr, 0, nullptr}};
static PyModuleDef module = {PyModuleDef_HEAD_INIT, "_automic_vault", nullptr, -1, methods};
PyMODINIT_FUNC PyInit__automic_vault() { return PyModule_Create(&module); }

static void check_path(const fs::path &path, const fs::path &bundle) {
  struct stat s;
  if (lstat(path.c_str(), &s) || s.st_uid != 0) throw std::runtime_error("Runtime must be root-owned");
  if (S_ISLNK(s.st_mode)) {
    auto resolved = fs::canonical(path).string();
    if (resolved.rfind(bundle.string() + "/", 0) != 0) throw std::runtime_error("Runtime link escapes bundle");
    return;
  }
  if ((!S_ISREG(s.st_mode) && !S_ISDIR(s.st_mode)) || (s.st_mode & 07022)) throw std::runtime_error("Unsafe runtime resource");
  if (access(path.c_str(), W_OK) == 0) throw std::runtime_error("Runtime is writable by this user");
  if (errno != EACCES && errno != EPERM && errno != EROFS) throw std::runtime_error("Cannot verify runtime write protection");
}
static void verify(const fs::path &bundle) {
  if (getuid() == 0 || geteuid() != getuid()) throw std::runtime_error("Run gcloud as an ordinary user");
  for (auto path = bundle; ; path = path.parent_path()) { check_path(path, bundle); if (path == path.parent_path()) break; }
  for (const auto &entry : fs::recursive_directory_iterator(bundle)) check_path(entry.path(), bundle);
  CFURLRef url = CFURLCreateFromFileSystemRepresentation(nullptr, (const UInt8 *)bundle.c_str(), strlen(bundle.c_str()), true);
  SecStaticCodeRef code = nullptr; SecRequirementRef requirement = nullptr;
  CFStringRef text = CFStringCreateWithCString(nullptr, identity, kCFStringEncodingUTF8);
  OSStatus status = SecRequirementCreateWithString(text, kSecCSDefaultFlags, &requirement);
  if (status == errSecSuccess) status = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code);
  if (status == errSecSuccess) status = SecStaticCodeCheckValidity(code, kSecCSStrictValidate | kSecCSCheckNestedCode | kSecCSCheckAllArchitectures, requirement);
  if (code) CFRelease(code); if (requirement) CFRelease(requirement); CFRelease(text); CFRelease(url);
  if (status != errSecSuccess) throw std::runtime_error("Invalid gcloud Isotope signature");
}
static void checked(PyStatus status) { if (PyStatus_Exception(status)) Py_ExitStatusException(status); }
int main(int argc, char **argv) {
  try {
    char executable[PATH_MAX], resolved[PATH_MAX], cwd[PATH_MAX]; uint32_t size = sizeof(executable);
    if (_NSGetExecutablePath(executable, &size) || !realpath(executable, resolved) || !getcwd(cwd, sizeof(cwd))) throw std::runtime_error("Cannot resolve gcloud execution");
    target = resolved; original_cwd = cwd;
    if (target != "/opt/av/gcloud/Gcloud.app/Contents/MacOS/gcloud") throw std::runtime_error("Run av harden gcloud to install the protected runtime");
    if (!valid_utf8(original_cwd)) throw std::runtime_error("Working directory must be UTF-8");
    for (int i = 1; i < argc; ++i) {
      arguments.emplace_back(argv[i]);
      if (!valid_utf8(arguments.back())) throw std::runtime_error("Arguments must be UTF-8");
    }
    auto contents = fs::path(target).parent_path().parent_path(); verify(contents.parent_path());
    struct rlimit limit = {0, 0};
    if (setrlimit(RLIMIT_CORE, &limit)) throw std::runtime_error("Cannot disable credential core dumps");
    PyImport_AppendInittab("_automic_vault", PyInit__automic_vault);
    PyConfig configuration; PyConfig_InitIsolatedConfig(&configuration);
    configuration.parse_argv = 0; configuration.site_import = 0; configuration.write_bytecode = 0;
    checked(PyConfig_SetBytesString(&configuration, &configuration.home, (contents / "Resources/python").c_str()));
    checked(PyConfig_SetBytesString(&configuration, &configuration.program_name, target.c_str()));
    checked(PyConfig_SetBytesArgv(&configuration, argc, argv));
    checked(PyConfig_SetBytesString(&configuration, &configuration.run_filename, (contents / "Resources/bootstrap.py").c_str()));
    checked(Py_InitializeFromConfig(&configuration)); PyConfig_Clear(&configuration);
    return Py_RunMain();
  } catch (const std::exception &error) { fprintf(stderr, "gcloud Isotope: %s\n", error.what()); return 1; }
}
