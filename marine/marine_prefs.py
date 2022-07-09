from ctypes import CDLL, POINTER, byref, c_char_p, c_int, c_ubyte, c_uint


class MarinePreferences:
    def __init__(self, marine_cdll: CDLL):
        self._marine = marine_cdll

        self.MARINE_PREFS_BAD_MODULE_NAME = c_int.in_dll(
            self._marine, "MARINE_PREFS_BAD_MODULE_NAME"
        ).value
        self.MARINE_PREFS_BAD_PREF_NAME = c_int.in_dll(
            self._marine, "MARINE_PREFS_BAD_PREF_NAME"
        ).value
        self.MARINE_PREFS_BAD_PREF_TYPE = c_int.in_dll(
            self._marine, "MARINE_PREFS_BAD_PREF_TYPE"
        ).value

        self._marine.marine_prefs_set_bool.argtypes = [c_char_p, c_char_p, c_ubyte]
        self._marine.marine_prefs_set_bool.restype = c_int

        self._marine.marine_prefs_get_bool.argtypes = [
            c_char_p,
            c_char_p,
            POINTER(c_ubyte),
        ]
        self._marine.marine_prefs_get_bool.restype = c_int

        self._marine.marine_prefs_set_uint.argtypes = [c_char_p, c_char_p, c_uint]
        self._marine.marine_prefs_set_uint.restype = c_int

        self._marine.marine_prefs_get_uint.argtypes = [
            c_char_p,
            c_char_p,
            POINTER(c_uint),
        ]
        self._marine.marine_prefs_get_uint.restype = c_int

        self._marine.marine_prefs_set_str.argtypes = [c_char_p, c_char_p, c_char_p]
        self._marine.marine_prefs_set_str.restype = c_int

        self._marine.marine_prefs_get_str.argtypes = [
            c_char_p,
            c_char_p,
            POINTER(c_char_p),
        ]
        self._marine.marine_prefs_get_str.restype = c_int

    def set_bool(self, module_name: str, preference_name: str, value: bool):
        status = self._marine.marine_prefs_set_bool(
            module_name.encode(), preference_name.encode(), value
        )
        self._raise_for_pref_status(status, module_name, preference_name, "bool")

    def set_uint(self, module_name: str, preference_name: str, value: int):
        status = self._marine.marine_prefs_set_uint(
            module_name.encode(), preference_name.encode(), value
        )
        self._raise_for_pref_status(status, module_name, preference_name, "uint")

    def set_str(self, module_name: str, preference_name: str, value: str):
        status = self._marine.marine_prefs_set_str(
            module_name.encode(), preference_name.encode(), value.encode()
        )
        self._raise_for_pref_status(status, module_name, preference_name, "string")

    def get_bool(self, module_name: str, preference_name: str) -> bool:
        value = c_ubyte()
        status = self._marine.marine_prefs_get_bool(
            module_name.encode(), preference_name.encode(), byref(value)
        )
        self._raise_for_pref_status(status, module_name, preference_name, "bool")
        return bool(value)

    def get_uint(self, module_name: str, preference_name: str) -> int:
        value = c_uint()
        status = self._marine.marine_prefs_get_uint(
            module_name.encode(), preference_name.encode(), byref(value)
        )
        self._raise_for_pref_status(status, module_name, preference_name, "uint")
        return int.from_bytes(value, "little")

    def get_str(self, module_name: str, preference_name: str) -> str:
        value = c_char_p(b"")
        status = self._marine.marine_prefs_get_str(
            module_name.encode(), preference_name.encode(), byref(value)
        )
        self._raise_for_pref_status(status, module_name, preference_name, "string")
        return value.value.decode("utf-8")

    def _raise_for_pref_status(
        self, status: int, module_name: str, preference_name: str, desired_type: str
    ):
        if status == self.MARINE_PREFS_BAD_MODULE_NAME:
            raise ValueError(f"Bad module name {module_name}")
        elif status == self.MARINE_PREFS_BAD_PREF_NAME:
            raise ValueError(f"Bad preference name {preference_name}")
        elif status == self.MARINE_PREFS_BAD_PREF_TYPE:
            raise TypeError(
                f"Preference {module_name}.{preference_name} is not a {desired_type}"
            )
