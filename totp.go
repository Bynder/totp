package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

func TOTPNow(secret string, period int) (string, error) {
	return TOTP(secret, time.Now().Unix(), period)
}

func TOTP(secret string, timestamp int64, period int) (string, error) {
	interval := timestamp / int64(period)
	return HOTP(secret, int(interval))
}

func HOTP(secret string, key int) (string, error) {
	realKey, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", errors.New("Secret not base32 ecnoded")
	}

	var buf = make([]byte, 8)

	binary.BigEndian.PutUint64(buf, uint64(key))

	mac := hmac.New(sha1.New, realKey)
	mac.Write(buf)
	macsum := mac.Sum(nil)

	offset := macsum[19] & 15

	otp_input := make([]byte, 4)
	copy(otp_input, macsum[offset:offset+4])
	intermediate := binary.BigEndian.Uint32(otp_input)
	token := (intermediate & 0x7fffffff) % 1000000
	return fmt.Sprintf("%06d", uint64(token)), nil
}

func ValidateTOTP(secret string, timestamp int64, period int, drift int, code string) bool {
	for x := -drift; x <= drift; x++ {
		token, _ := TOTP(secret, timestamp+int64(x*period), period)
		if token == code {
			return true
		}
	}
	return false
}
