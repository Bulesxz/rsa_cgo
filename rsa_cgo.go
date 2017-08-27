package rsa_cgo

// #cgo LDFLAGS: ./c/librsa.a -L/usr/local/Cellar/openssl@1.1/1.1.0f/lib/ -lcrypto -lssl  -lstdc++
// #include "./c/rsa.h"
// #include <stdlib.h>
import "C"

import "unsafe"

func CgoLoadPrivateKey(pri_file string) unsafe.Pointer {
	cstr := C.CString(pri_file)
	defer C.free(unsafe.Pointer(cstr))

	return C.CLoadPrivateKey(cstr)
}

func CgoRsaSign(pri unsafe.Pointer, ori string) string {
	cstr := C.CString(ori)
	defer C.free(unsafe.Pointer(cstr))

	sign := C.CRsaSign(pri, cstr)
	if sign == nil {
		return ""
	}
	return C.GoString(sign)
}

func CgoLoadPublicKey(pri_file string) unsafe.Pointer {
	cstr := C.CString(pri_file)
	defer C.free(unsafe.Pointer(cstr))

	return C.CLoadPublicKey(cstr)
}

func CRsaVerify(pub unsafe.Pointer, ori, sign string) bool {
	cstr_ori := C.CString(ori)
	defer C.free(unsafe.Pointer(cstr_ori))

	cstr_sign := C.CString(sign)
	defer C.free(unsafe.Pointer(cstr_sign))

	ok := C.CRsaVerify(pub, cstr_ori, cstr_sign)
	if ok == 0 {
		return false
	} else {
		return true
	}
}

func CgoDestoryKey(pri unsafe.Pointer) {
	C.CDestoryKey(pri)
}
