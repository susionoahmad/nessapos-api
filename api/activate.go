package handler

import (
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

func Handler(w http.ResponseWriter, r *http.Request) {
	// 1. Ambil input
	var req struct {
		SerialKey string `json:"serial_key"`
		DeviceID  string `json:"device_id"`
	}
	body, _ := io.ReadAll(r.Body)
	json.Unmarshal(body, &req)

	cleanKey := strings.TrimSpace(req.SerialKey)
	cleanDeviceID := strings.TrimSpace(req.DeviceID)

	// 2. Cek Konfigurasi (Internal Check)
	sbUrl := os.Getenv("SUPABASE_URL")
	sbKey := os.Getenv("SUPABASE_SERVICE_ROLE_KEY")
	privKeyB64 := os.Getenv("LICENSE_PRIVATE_KEY")

	if sbUrl == "" || sbKey == "" {
		sendError(w, "Konfigurasi Server Belum Lengkap (Vercel Env Vars Kosong)", 500)
		return
	}

	// 3. Panggil Supabase
	apiUrl := fmt.Sprintf("%s/rest/v1/licenses?serial_key=eq.%s&select=*", sbUrl, cleanKey)
	client := &http.Client{Timeout: 15 * time.Second}
	sbReq, _ := http.NewRequest("GET", apiUrl, nil)
	sbReq.Header.Set("apikey", sbKey)
	sbReq.Header.Set("Authorization", "Bearer "+sbKey)

	resp, err := client.Do(sbReq)
	if err != nil {
		sendError(w, "Gagal koneksi ke Supabase: "+err.Error(), 500)
		return
	}
	defer resp.Body.Close()

	// Jika Supabase menolak (Penyebab 401 sesungguhnya)
	if resp.StatusCode != 200 {
		var sbErr map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&sbErr)
		msg, _ := sbErr["message"].(string)
		sendError(w, fmt.Sprintf("Supabase Error (%d): %s", resp.StatusCode, msg), 401)
		return
	}

	var result []map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	if len(result) == 0 {
		sendError(w, fmt.Sprintf("Serial Key [%s] tidak ditemukan di database", cleanKey), 404)
		return
	}

	licenseData := result[0]
	isActive, _ := licenseData["is_active"].(bool)
	if !isActive {
		sendError(w, "Lisensi ini statusnya tidak aktif (Blocked)", 403)
		return
	}

	// 4. Data Lisensi
	customerName, _ := licenseData["customer_name"].(string)
	expiryDays := 365
	if val, ok := licenseData["expiry_days"].(float64); ok {
		expiryDays = int(val)
	}
	
	now := time.Now()
	expiry := ""
	if expiryDays > 0 {
		expiry = now.AddDate(0, 0, expiryDays).Format("2006-01-02")
	}

	// 5. Digital Signing
	privKeyBytes, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(privKeyB64))
	if len(privKeyBytes) != ed25519.PrivateKeySize {
		sendError(w, "Internal Error: Private Key di Vercel tidak valid", 500)
		return
	}
	
	privKey := ed25519.PrivateKey(privKeyBytes)
	issuedAt := now.Format(time.RFC3339)
	msgData := fmt.Sprintf("%s|%s|%s|%s", customerName, cleanDeviceID, issuedAt, expiry)
	sig := ed25519.Sign(privKey, []byte(msgData))

	// 6. Respon Sukses
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"payload": map[string]string{
			"issued_to": customerName,
			"device_id": cleanDeviceID,
			"issued_at": issuedAt,
			"expiry":    expiry,
		},
		"signature": base64.StdEncoding.EncodeToString(sig),
	})
}

func sendError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"message": msg})
}
