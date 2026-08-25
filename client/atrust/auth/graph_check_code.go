package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"

	"github.com/mythologyli/zju-connect/client/authchallenge"
)

type graphCheckCodePayload struct {
	Coordinates [][]int `json:"coordinates"`
	Width       int     `json:"width"`
	Height      int     `json:"height"`
}

func graphCheckCodeFromResponse(response authchallenge.ClickCaptchaResponse, imgData []byte) (string, error) {
	coordinates := make([][]int, 0, len(response.Points))
	for _, point := range response.Points {
		coordinates = append(coordinates, []int{point.X, point.Y})
	}
	width, height := response.Width, response.Height
	if width <= 0 || height <= 0 {
		var err error
		width, height, err = decodeImageSize(imgData)
		if err != nil {
			return "", fmt.Errorf("failed to decode captcha image size: %w", err)
		}
	}
	return marshalGraphCheckCode(graphCheckCodePayload{
		Coordinates: coordinates,
		Width:       width,
		Height:      height,
	})
}

func isValidCoordinates(coordinates [][]int) bool {
	if len(coordinates) == 0 {
		return false
	}
	for _, pair := range coordinates {
		if len(pair) != 2 {
			return false
		}
	}
	return true
}

func decodeImageSize(imgData []byte) (int, int, error) {
	if len(imgData) == 0 {
		return 0, 0, fmt.Errorf("empty image data")
	}
	cfg, _, err := image.DecodeConfig(bytes.NewReader(imgData))
	if err != nil {
		return 0, 0, err
	}
	if cfg.Width <= 0 || cfg.Height <= 0 {
		return 0, 0, fmt.Errorf("invalid image dimensions: %dx%d", cfg.Width, cfg.Height)
	}
	return cfg.Width, cfg.Height, nil
}

func marshalGraphCheckCode(payload graphCheckCodePayload) (string, error) {
	if !isValidCoordinates(payload.Coordinates) {
		return "", fmt.Errorf("invalid coordinates")
	}
	if payload.Width <= 0 || payload.Height <= 0 {
		return "", fmt.Errorf("invalid dimensions: %dx%d", payload.Width, payload.Height)
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
