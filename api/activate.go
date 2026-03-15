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

	"github.com/supabase-community/supabase-go"
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

	var req struct {
		SerialKey string `json:"serial_key"`
		DeviceID  string `json:"device_id"`
	}
	body, _ := io.ReadAll(r.Body)
	json.Unmarshal(body, &req)

	sbUrl := os.Getenv("SUPABASE_URL")
	sbKey := os.Getenv("SUPABASE_SERVICE_ROLE_KEY") 
	client, err := supabase.NewClient(sbUrl, sbKey, nil)
	if err != nil {
		sendError(w, "Server Error: Database connection failed", 500)
		return
	}

	var result []map[string]interface{}
	err = client.DB.From("licenses").Select("*").Eq("serial_key", req.SerialKey).Eq("is_active", "true").Execute(&result)

	if err != nil || len(result) == 0 {
		sendError(w, "Serial Key tidak valid", 401)
		return
	}

	licenseData := result[0]
	dbDeviceID, _ := licenseData["device_id"].(string)

	if dbDeviceID == "" {
		updateData := map[string]interface{}{
			"device_id":    req.DeviceID,
			"activated_at": time.Now().Format(time.RFC3339),
		}
		client.DB.From("licenses").Update(updateData).Eq("serial_key", req.SerialKey).Execute(nil)
	} else if strings.TrimSpace(dbDeviceID) != strings.TrimSpace(req.DeviceID) {
		sendError(w, "Alat sudah terdaftar di perangkat lain", 403)
		return
	}

	customerName, _ := licenseData["customer_name"].(string)
	expiryDays := int(licenseData["expiry_days"].(float64))
	
	now := time.Now()
	issuedAt := now.Format(time.RFC3339)
	var expiry string
	if expiryDays > 0 {
		expiry = now.AddDate(0, 0, expiryDays).Format("2006-01-02")
	}

	privKeyB64 := os.Getenv("LICENSE_PRIVATE_KEY")
	privKeyBytes, _ := base64.StdEncoding.DecodeString(privKeyB64)
	privKey := ed25519.PrivateKey(privKeyBytes)

	payload := LicensePayload{
		IssuedTo: customerName,
		DeviceID: req.DeviceID,
		IssuedAt: issuedAt,
		Expiry:   expiry,
	}

	msg := fmt.Sprintf("%s|%s|%s|%s", payload.IssuedTo, payload.DeviceID, payload.IssuedAt, payload.Expiry)
	sig := ed25519.Sign(privKey, []byte(msg))

	resp := LicenseFile{
		Payload:   payload,
		Signature: base64.StdEncoding.EncodeToString(sig),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func sendError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"message": msg})
}
