package handler

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type LicensePayload struct {
	IssuedTo string `json:"issued_to"`
	DeviceID string `json:"device_id"`
	IssuedAt string `json:"issued_at"`
	Expiry   string `json:"expiry"`
}

type LicenseFile struct {
	Payload   LicensePayload `json:"payload"`
	Signature string         `json:"signature"`
}

func Handler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. Ambil input dari NessaPOS
	var req struct {
		SerialKey string `json:"serial_key"`
		DeviceID  string `json:"device_id"`
	}
	body, _ := io.ReadAll(r.Body)
	json.Unmarshal(body, &req)

	if req.SerialKey == "" || req.DeviceID == "" {
		sendError(w, "Serial Key dan Device ID wajib diisi", 400)
		return
	}

	// 2. Cek Lisensi ke Supabase via REST API
	sbUrl := os.Getenv("SUPABASE_URL")
	sbKey := os.Getenv("SUPABASE_SERVICE_ROLE_KEY")
	
	// Query: Cari serial_key yang is_active-nya true
	apiUrl := fmt.Sprintf("%s/rest/v1/licenses?serial_key=eq.%s&is_active=eq.true&select=*", sbUrl, req.SerialKey)
	
	client := &http.Client{Timeout: 10 * time.Second}
	sbReq, _ := http.NewRequest("GET", apiUrl, nil)
	sbReq.Header.Set("apikey", sbKey)
	sbReq.Header.Set("Authorization", "Bearer "+sbKey)

	resp, err := client.Do(sbReq)
	if err != nil {
		sendError(w, "Gagal koneksi ke database pusat", 500)
		return
	}
	defer resp.Body.Close()

	var result []map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	if len(result) == 0 {
		sendError(w, "Serial Key tidak ditemukan atau sudah tidak aktif", 401)
		return
	}

	licenseData := result[0]
	dbDeviceID, _ := licenseData["device_id"].(string)

	// 3. Cek/Binding Device ID
	if dbDeviceID == "" {
		// Update Device ID jika masih kosong
		updateUrl := fmt.Sprintf("%s/rest/v1/licenses?serial_key=eq.%s", sbUrl, req.SerialKey)
		nowStr := time.Now().Format(time.RFC3339)
		updateBody, _ := json.Marshal(map[string]string{
			"device_id":    req.DeviceID,
			"activated_at": nowStr,
		})
		
		upReq, _ := http.NewRequest("PATCH", updateUrl, bytes.NewBuffer(updateBody))
		upReq.Header.Set("apikey", sbKey)
		upReq.Header.Set("Authorization", "Bearer "+sbKey)
		upReq.Header.Set("Content-Type", "application/json")
		upReq.Header.Set("Prefer", "return=representation")
		client.Do(upReq)
	} else if strings.TrimSpace(dbDeviceID) != strings.TrimSpace(req.DeviceID) {
		sendError(w, "Serial Key ini sudah digunakan di PC lain", 403)
		return
	}

	// 4. Hitung Tanggal & Data
	customerName, _ := licenseData["customer_name"].(string)
	expiryDays := 365
	if val, ok := licenseData["expiry_days"].(float64); ok {
		expiryDays = int(val)
	}
	
	now := time.Now()
	issuedAt := now.Format(time.RFC3339)
	expiry := ""
	if expiryDays > 0 {
		expiry = now.AddDate(0, 0, expiryDays).Format("2006-01-02")
	}

	// 5. Tanda Tangani Lisensi (Ed25519)
	privKeyB64 := os.Getenv("LICENSE_PRIVATE_KEY")
	privKeyBytes, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(privKeyB64))
	if len(privKeyBytes) != ed25519.PrivateKeySize {
		sendError(w, "Internal Error: Private Key Server tidak valid", 500)
		return
	}
	privKey := ed25519.PrivateKey(privKeyBytes)

	payload := LicensePayload{
		IssuedTo: customerName,
		DeviceID: req.DeviceID,
		IssuedAt: issuedAt,
		Expiry:   expiry,
	}

	msg := fmt.Sprintf("%s|%s|%s|%s", payload.IssuedTo, payload.DeviceID, payload.IssuedAt, payload.Expiry)
	sig := ed25519.Sign(privKey, []byte(msg))

	// 6. Respon
	finalResp := LicenseFile{
		Payload:   payload,
		Signature: base64.StdEncoding.EncodeToString(sig),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(finalResp)
}

func sendError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"message": msg})
}
