"""Use the macOS Security framework without putting passwords in argv."""

import ctypes as C


def _api():
    lib = C.CDLL("/System/Library/Frameworks/Security.framework/Security")
    lib.SecKeychainFindGenericPassword.argtypes = [
        C.c_void_p,
        C.c_uint32,
        C.c_char_p,
        C.c_uint32,
        C.c_char_p,
        C.POINTER(C.c_uint32),
        C.POINTER(C.c_void_p),
        C.POINTER(C.c_void_p),
    ]
    lib.SecKeychainAddGenericPassword.argtypes = [
        C.c_void_p,
        C.c_uint32,
        C.c_char_p,
        C.c_uint32,
        C.c_char_p,
        C.c_uint32,
        C.c_void_p,
        C.POINTER(C.c_void_p),
    ]
    lib.SecKeychainItemModifyAttributesAndData.argtypes = [
        C.c_void_p,
        C.c_void_p,
        C.c_uint32,
        C.c_void_p,
    ]
    lib.SecKeychainItemFreeContent.argtypes = [C.c_void_p, C.c_void_p]
    return lib


def _service(gateway):
    return ("dual-vpn-router:" + gateway["name"] + ":" + gateway["url"]).encode()


def read(gateway):
    lib = _api()
    service, account = _service(gateway), gateway["username"].encode()
    length, data = C.c_uint32(), C.c_void_p()
    status = lib.SecKeychainFindGenericPassword(
        None,
        len(service),
        service,
        len(account),
        account,
        C.byref(length),
        C.byref(data),
        None,
    )
    if status == -25300:
        return None
    if status:
        raise RuntimeError(f"Keychain read failed ({status}).")
    try:
        return C.string_at(data, length.value).decode()
    finally:
        lib.SecKeychainItemFreeContent(None, data)


def write(gateway, password):
    lib = _api()
    service, account, secret = (
        _service(gateway),
        gateway["username"].encode(),
        password.encode(),
    )
    status = lib.SecKeychainAddGenericPassword(
        None, len(service), service, len(account), account, len(secret), secret, None
    )
    if status == -25299:
        item = C.c_void_p()
        status = lib.SecKeychainFindGenericPassword(
            None,
            len(service),
            service,
            len(account),
            account,
            None,
            None,
            C.byref(item),
        )
        if not status:
            status = lib.SecKeychainItemModifyAttributesAndData(item, None, len(secret), secret)
            cf = C.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
            cf.CFRelease.argtypes = [C.c_void_p]
            cf.CFRelease(item)
    if status:
        raise RuntimeError(f"Keychain write failed ({status}).")
