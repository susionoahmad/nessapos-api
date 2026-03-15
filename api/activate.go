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
	var req struct {
		SerialKey string `json:"serial_key"`
		DeviceID  string `json:"device_id"`
	}
	body, _ := io.ReadAll(r.Body)
	json.Unmarshal(body, &req)

	cleanKey := strings.TrimSpace(req.SerialKey)
	cleanDeviceID := strings.TrimSpace(req.DeviceID)

	sbUrl := os.Getenv("SUPABASE_URL")
	sbKey := os.Getenv("SUPABASE_SERVICE_ROLE_KEY")
	privKeyB64 := os.Getenv("LICENSE_PRIVATE_KEY")

	// 1. Cari Lisensi
	apiUrl := fmt.Sprintf("%s/rest/v1/licenses?serial_key=eq.%s&select=*", sbUrl, cleanKey)
	client := &http.Client{Timeout: 15 * time.Second}
	sbReq, _ := http.NewRequest("GET", apiUrl, nil)
	sbReq.Header.Set("apikey", sbKey)
	sbReq.Header.Set("Authorization", "Bearer "+sbKey)

	resp, _ := client.Do(sbReq)
	defer resp.Body.Close()

	var result []map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	if len(result) == 0 {
		sendError(w, "Serial Key tidak ditemukan", 401)
		return
	}

	licenseData := result[0]
	dbDeviceID, _ := licenseData["device_id"].(string)
	activatedAtStr, _ := licenseData["activated_at"].(string)
	expiryDateStr, _ := licenseData["expiry_date"].(string)
	
	finalExpiry := expiryDateStr

	// 2. LOGIKA AKTIVASI PERTAMA VS PINDAH PC
	if dbDeviceID == "" {
		updateMap := make(map[string]string)
		updateMap["device_id"] = cleanDeviceID
		
		// JIKA INI AKTIVASI PERTAMA KALI (Belum pernah diaktifkan dimanapun)
		if activatedAtStr == "" {
			now := time.Now()
			updateMap["activated_at"] = now.Format(time.RFC3339)
			
			// Hitung Expiry Date berdasarkan durasi hari
			expiryDays := 0
			if val, ok := licenseData["expiry_days"].(float64); ok {
				expiryDays = int(val)
			}
			
			if expiryDays > 0 {
				finalExpiry = now.AddDate(0, 0, expiryDays).Format("2006-01-02")
				updateMap["expiry_date"] = finalExpiry
			}
		}

		// Kirim update ke database
		updateUrl := fmt.Sprintf("%s/rest/v1/licenses?serial_key=eq.%s", sbUrl, cleanKey)
		updateBody, _ := json.Marshal(updateMap)
		upReq, _ := http.NewRequest("PATCH", updateUrl, bytes.NewBuffer(updateBody))
		upReq.Header.Set("apikey", sbKey)
		upReq.Header.Set("Authorization", "Bearer "+sbKey)
		upReq.Header.Set("Content-Type", "application/json")
		client.Do(upReq)
	} else if strings.TrimSpace(dbDeviceID) != cleanDeviceID {
		sendError(w, "Lisensi ini sudah terkunci untuk perangkat lain", 403)
		return
	}

	// 3. Cek apakah sisa harinya sudah habis (Kadaluarsa)
	if finalExpiry != "" {
		expiryTime, _ := time.Parse("2006-01-02", finalExpiry)
		if time.Now().After(expiryTime.Add(24 * time.Hour)) {
			sendError(w, "Masa aktif lisensi ini sudah habis ("+finalExpiry+")", 402)
			return
		}
	}

	// 4. Generate Certificate
	customerName, _ := licenseData["customer_name"].(string)
	privKeyBytes, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(privKeyB64))
	privKey := ed25519.PrivateKey(privKeyBytes)

	issuedAt := time.Now().Format(time.RFC3339)
	msg := fmt.Sprintf("%s|%s|%s|%s", customerName, cleanDeviceID, issuedAt, finalExpiry)
	sig := ed25519.Sign(privKey, []byte(msg))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"payload": map[string]string{
			"issued_to": customerName,
			"device_id": cleanDeviceID,
			"issued_at": issuedAt,
			"expiry":    finalExpiry,
		},
		"signature": base64.StdEncoding.EncodeToString(sig),
	})
}

func sendError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"message": msg})
}
