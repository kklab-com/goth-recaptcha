package recaptcha

import (
	"encoding/json"
	"io/ioutil"
	"net/url"
	"time"

	"github.com/hashicorp/go-retryablehttp"
)

var Endpoint = "https://www.google.com/recaptcha/api/siteverify"
var ScoreThreshold = .7

func SiteVerify(secret string, response string) *VerifyResponse {
	form := url.Values{}
	form.Set("secret", secret)
	form.Set("response", response)
	client := retryablehttp.NewClient()
	client.Logger = nil
	if resp, e := client.PostForm(Endpoint, form); e == nil {
		if body, e := ioutil.ReadAll(resp.Body); e == nil {
			defer resp.Body.Close()
			verifyResponse := VerifyResponse{}
			if json.Unmarshal(body, &verifyResponse) == nil {
				return &verifyResponse
			}
		}
	}

	return nil
}

type VerifyResponse struct {
	Success        bool      `json:"success"`
	Score          float64   `json:"score"`
	Action         string    `json:"action"`
	ChallengeTs    time.Time `json:"challenge_ts"`
	Hostname       string    `json:"hostname"`
	ApkPackageName string    `json:"apk_package_name"`
	ErrorCodes     []string  `json:"error-codes"`
}

func (v *VerifyResponse) SimpleCheck() bool {
	if v.Success && v.Score >= ScoreThreshold {
		return true
	}

	return false
}
