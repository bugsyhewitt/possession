package detect

import (
	"net/http"
	"testing"

	"github.com/bugsyhewitt/possession/internal/model"
)

func sample(status int, body string) *model.Response {
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	return &model.Response{
		Status:  status,
		Headers: h,
		Body:    []byte(body),
	}
}

func TestClampBaselineSamples(t *testing.T) {
	if ClampBaselineSamples(0) != MinBaselineSamples {
		t.Errorf("clamp low")
	}
	if ClampBaselineSamples(999) != MaxBaselineSamples {
		t.Errorf("clamp high")
	}
	if ClampBaselineSamples(3) != 3 {
		t.Errorf("identity")
	}
}

func TestCalibrate_N1Skipped(t *testing.T) {
	res := Calibrate([]*model.Response{sample(200, `{"x":1}`)})
	if !res.Skipped {
		t.Errorf("expected calibration skipped at N=1")
	}
	if res.EffThreshold != DefaultThreshold {
		t.Errorf("eff threshold: want %v got %v", DefaultThreshold, res.EffThreshold)
	}
	if len(res.Notes) == 0 {
		t.Errorf("expected calibration-skipped note")
	}
}

func TestCalibrate_StableDeterministic(t *testing.T) {
	body := `{"a":1,"b":2,"c":3,"d":4}`
	res := Calibrate([]*model.Response{sample(200, body), sample(200, body), sample(200, body)})
	if res.Stability != 1.0 {
		t.Errorf("identical bodies should give stability 1.0, got %v", res.Stability)
	}
	if res.Noisy {
		t.Errorf("identical bodies should not be noisy")
	}
}

func TestCalibrate_NoisyEndpoint(t *testing.T) {
	// Three completely different long bodies — should fall below NoisyEndpointThreshold.
	res := Calibrate([]*model.Response{
		sample(200, "alpha bravo charlie delta echo foxtrot golf hotel india juliet"),
		sample(200, "kilo lima mike november oscar papa quebec romeo sierra tango"),
		sample(200, "uniform victor whiskey xray yankee zulu one two three four"),
	})
	if !res.Noisy {
		t.Errorf("disjoint bodies should be noisy, stability=%v", res.Stability)
	}
}

func TestCalibrate_BaselineNon2xx(t *testing.T) {
	res := Calibrate([]*model.Response{sample(500, ""), sample(500, ""), sample(500, "")})
	if !res.BaselineFailed {
		t.Errorf("expected BaselineFailed on non-2xx samples")
	}
	if len(res.Notes) == 0 {
		t.Errorf("expected baseline-not-2xx note")
	}
}

func TestCalibrate_NoSamples(t *testing.T) {
	res := Calibrate(nil)
	if !res.BaselineFailed {
		t.Errorf("expected BaselineFailed on no samples")
	}
}
