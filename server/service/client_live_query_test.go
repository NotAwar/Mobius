package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/notawar/mobius/pkg/mobiushttp"
	"github.com/notawar/mobius/server/mobius"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLiveQueryWithContext(t *testing.T) {
	upgrader := websocket.Upgrader{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/latest/mobius/queries/run_by_identifiers":
			resp := createDistributedQueryCampaignResponse{
				Campaign: &mobius.DistributedQueryCampaign{
					UpdateCreateTimestamps: mobius.UpdateCreateTimestamps{
						CreateTimestamp: mobius.CreateTimestamp{CreatedAt: time.Now()},
						UpdateTimestamp: mobius.UpdateTimestamp{UpdatedAt: time.Now()},
					},
					Metrics: mobius.TargetMetrics{
						TotalHosts:           1,
						OnlineHosts:          1,
						OfflineHosts:         0,
						MissingInActionHosts: 0,
						NewHosts:             0,
					},
					ID:      99,
					QueryID: 42,
					Status:  0,
					UserID:  23,
				},
			}
			err := json.NewEncoder(w).Encode(resp)
			assert.NoError(t, err)
		case "/api/latest/mobius/results/websocket":
			ws, _ := upgrader.Upgrade(w, r, nil)
			defer ws.Close()

			for {
				time.Sleep(1 * time.Second)
				mt, message, _ := ws.ReadMessage()
				if string(message) == `{"type":"auth","data":{"token":"1234"}}` {
					return
				}
				if string(message) == `{"type":"select_campaign","data":{"campaign_id":99}}` {
					return
				}

				result := struct {
					Type string                       `json:"type"`
					Data mobius.DistributedQueryResult `json:"data"`
				}{
					Type: "result",
					Data: mobius.DistributedQueryResult{
						DistributedQueryCampaignID: 99,
						Host: mobius.ResultHostData{
							ID:       23,
							Hostname: "somehostaaa",
						},
						Rows: []map[string]string{
							{
								"col1": "aaa",
								"col2": "bbb",
							},
						},
						Error: nil,
					},
				}
				b, err := json.Marshal(result)
				assert.NoError(t, err)
				_ = ws.WriteMessage(mt, b)
			}
		}
	}))
	defer ts.Close()

	baseURL, err := url.Parse(ts.URL)
	require.NoError(t, err)
	client := &Client{
		baseClient: &baseClient{
			baseURL:            baseURL,
			http:               mobiushttp.NewClient(),
			insecureSkipVerify: false,
			urlPrefix:          "",
		},
		token:        "1234",
		outputWriter: nil,
	}
	ctx, cancelFunc := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelFunc()

	res, err := client.LiveQueryWithContext(ctx, "select 1;", nil, nil, []string{"host1"})
	require.NoError(t, err)

	gotResults := false
	go func() {
		for {
			select {
			case <-res.Results():
				gotResults = true
				cancelFunc()
			case err := <-res.Errors():
				require.NoError(t, err)
			case <-ctx.Done():
				return
			}
		}
	}()
	<-ctx.Done()
	assert.True(t, gotResults)
}
