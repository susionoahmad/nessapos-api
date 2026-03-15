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

	// 1. Ambil input
	var req struct {
		SerialKey string `json:"serial_key"`
		DeviceID  string `json:"device_id"`
	}
	body, _ := io.ReadAll(r.Body)
	json.Unmarshal(body, &req)

	// MEMBERSIHKAN INPUT (Sangat Penting)
	cleanKey := strings.TrimSpace(req.SerialKey)
	cleanDeviceID := strings.TrimSpace(req.DeviceID)

	if cleanKey == "" || cleanDeviceID == "" {
		sendError(w, "Harap masukkan Serial Key yang valid", 400)
		return
	}

	// 2. Cek Lisensi ke Supabase REST API
	sbUrl := os.Getenv("SUPABASE_URL")
	sbKey := os.Getenv("SUPABASE_SERVICE_ROLE_KEY")
	
	// Gunakan filter yang lebih ketat tapi fleksibel
	apiUrl := fmt.Sprintf("%s/rest/v1/licenses?serial_key=eq.%s&select=*", sbUrl, cleanKey)
	
	client := &http.Client{Timeout: 15 * time.Second}
	sbReq, _ := http.NewRequest("GET", apiUrl, nil)
	sbReq.Header.Set("apikey", sbKey)
	sbReq.Header.Set("Authorization", "Bearer "+sbKey)

	resp, err := client.Do(sbReq)
	if err != nil {
		sendError(w, "Database pusat tidak merespon", 500)
		return
	}
	defer resp.Body.Close()

	var result []map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	// JIKA TIDAK KETEMU (Penyebab 401)
	if len(result) == 0 {
		sendError(w, "Serial Key ["+cleanKey+"] tidak terdaftar di sistem kami", 401)
		return
	}

	licenseData := result[0]
	
	// Cek apakah lisensi aktif
	isActive, ok := licenseData["is_active"].(bool)
	if ok && !isActive {
		sendError(w, "Lisensi ini telah dinonaktifkan/diblokir", 401)
		return
	}

	dbDeviceID, _ := licenseData["device_id"].(string)

	// 3. Binding Hardware ID
	if dbDeviceID == "" || dbDeviceID == nullString() {
		// Update pertama kali
		updateUrl := fmt.Sprintf("%s/rest/v1/licenses?id=eq.%v", sbUrl, licenseData["id"])
		updateBody, _ := json.Marshal(map[string]string{
			"device_id":    cleanDeviceID,
			"activated_at": time.Now().Format(time.RFC3339),
		})
		
		upReq, _ := http.NewRequest("PATCH", updateUrl, bytes.NewBuffer(updateBody))
		upReq.Header.Set("apikey", sbKey)
		upReq.Header.Set("Authorization", "Bearer "+sbKey)
		upReq.Header.Set("Content-Type", "application/json")
		client.Do(upReq)
	} else if strings.TrimSpace(dbDeviceID) != cleanDeviceID {
		sendError(w, "Lisensi ini sudah terkunci untuk perangkat lain", 403)
		return
	}

	// 4. Data Lisensi
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

	// 5. Signing
	privKeyB64 := os.Getenv("LICENSE_PRIVATE_KEY")
	privKeyBytes, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(privKeyB64))
	privKey := ed25519.PrivateKey(privKeyBytes)

	payload := LicensePayload{
		IssuedTo: customerName,
		DeviceID: cleanDeviceID,
		IssuedAt: issuedAt,
		Expiry:   expiry,
	}

	msg := fmt.Sprintf("%s|%s|%s|%s", payload.IssuedTo, payload.DeviceID, payload.IssuedAt, payload.Expiry)
	sig := ed25519.Sign(privKey, []byte(msg))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(LicenseFile{
		Payload:   payload,
		Signature: base64.StdEncoding.EncodeToString(sig),
	})
}

func nullString() string { return "" }

func sendError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"message": msg})
}
