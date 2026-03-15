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

	// 2. Cek Konfigurasi
	sbUrl := os.Getenv("SUPABASE_URL")
	sbKey := os.Getenv("SUPABASE_SERVICE_ROLE_KEY")
	privKeyB64 := os.Getenv("LICENSE_PRIVATE_KEY")

	if sbUrl == "" || sbKey == "" {
		sendError(w, "Konfigurasi Server Vercel belum lengkap", 500)
		return
	}

	// 3. Cari Lisensi di Supabase
	apiUrl := fmt.Sprintf("%s/rest/v1/licenses?serial_key=eq.%s&select=*", sbUrl, cleanKey)
	client := &http.Client{Timeout: 15 * time.Second}
	sbReq, _ := http.NewRequest("GET", apiUrl, nil)
	sbReq.Header.Set("apikey", sbKey)
	sbReq.Header.Set("Authorization", "Bearer "+sbKey)

	resp, err := client.Do(sbReq)
	if err != nil {
		sendError(w, "Gagal koneksi ke database", 500)
		return
	}
	defer resp.Body.Close()

	var result []map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	if len(result) == 0 {
		sendError(w, "Serial Key tidak ditemukan", 404)
		return
	}

	licenseData := result[0]
	dbDeviceID, _ := licenseData["device_id"].(string)

	// 4. LOGIKA BINDING (Simpan ke Database jika masih kosong)
	if dbDeviceID == "" {
		updateUrl := fmt.Sprintf("%s/rest/v1/licenses?serial_key=eq.%s", sbUrl, cleanKey)
		updateData, _ := json.Marshal(map[string]string{
			"device_id":    cleanDeviceID,
			"activated_at": time.Now().Format(time.RFC3339),
		})
		
		upReq, _ := http.NewRequest("PATCH", updateUrl, bytes.NewBuffer(updateData))
		upReq.Header.Set("apikey", sbKey)
		upReq.Header.Set("Authorization", "Bearer "+sbKey)
		upReq.Header.Set("Content-Type", "application/json")
		
		// Eksekusi update ke Supabase
		client.Do(upReq)
	} else if strings.TrimSpace(dbDeviceID) != cleanDeviceID {
		sendError(w, "Lisensi ini sudah terkunci untuk perangkat lain", 403)
		return
	}

	// 5. Data untuk Lisensi
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

	// 6. Tanda Tangani Lisensi
	privKeyBytes, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(privKeyB64))
	privKey := ed25519.PrivateKey(privKeyBytes)
	
	issuedAt := now.Format(time.RFC3339)
	payload := map[string]string{
		"issued_to": customerName,
		"device_id": cleanDeviceID,
		"issued_at": issuedAt,
		"expiry":    expiry,
	}

	msg := fmt.Sprintf("%s|%s|%s|%s", payload["issued_to"], payload["device_id"], payload["issued_at"], payload["expiry"])
	sig := ed25519.Sign(privKey, []byte(msg))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"payload":   payload,
		"signature": base64.StdEncoding.EncodeToString(sig),
	})
}

func sendError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"message": msg})
}
