module github.com/MobiusDM/mobius/server/api

go 1.25.3

require (
	cloud.google.com/go/pubsub v1.45.1
	github.com/Masterminds/semver/v3 v3.3.1
	github.com/MobiusDM/mobius/shared v0.0.0-00010101000000-000000000000
	github.com/RobotsAndPencils/buford v0.14.0
	github.com/VividCortex/mysqlerr v0.0.0-20170204212430-6c6b55f8796f
	github.com/WatchBeam/clock v0.0.0-20170901150240-b08e6b4da7ea
	github.com/XSAM/otelsql v0.35.0
	github.com/andygrunwald/go-jira v1.16.0
	github.com/apex/log v1.9.0
	github.com/aws/aws-sdk-go v1.44.288
	github.com/aws/aws-sdk-go-v2/feature/cloudfront/sign v1.9.4
	github.com/beevik/etree v1.6.0
	github.com/blakesmith/ar v0.0.0-20190502131153-809d4375e1fb
	github.com/boltdb/bolt v1.3.1
	github.com/cavaliergopher/rpm v1.3.0
	github.com/cenkalti/backoff v2.2.1+incompatible
	github.com/cenkalti/backoff/v4 v4.3.0
	github.com/docker/go-units v0.5.0
	github.com/doug-martin/goqu/v9 v9.18.0
	github.com/facebookincubator/flog v0.0.0-20190930132826-d2511d0ce33c
	github.com/fatih/color v1.18.0
	github.com/getsentry/sentry-go v0.18.0
	github.com/ghodss/yaml v1.0.0
	github.com/github/smimesign v0.2.0
	github.com/go-json-experiment/json v0.0.0-20250517221953-25912455fbc8
	github.com/go-kit/kit v0.13.0
	github.com/go-kit/log v0.2.1
	github.com/go-sql-driver/mysql v1.9.3
	github.com/gocarina/gocsv v0.0.0-20220310154401-d4df709ca055
	github.com/golang-jwt/jwt/v4 v4.5.2
	github.com/gomodule/oauth1 v0.2.0
	github.com/gomodule/redigo v1.9.2
	github.com/google/go-cmp v0.7.0
	github.com/google/go-github/v37 v37.0.0
	github.com/google/uuid v1.6.0
	github.com/gorilla/mux v1.8.1
	github.com/gorilla/websocket v1.5.3
	github.com/groob/finalizer v0.0.0-20170707115354-4c2ed49aabda
	github.com/hashicorp/go-multierror v1.1.1
	github.com/igm/sockjs-go/v3 v3.0.2
	github.com/jmoiron/sqlx v1.4.0
	github.com/klauspost/compress v1.18.0
	github.com/kolide/launcher v1.0.12
	github.com/lib/pq v1.10.9
	github.com/mattermost/xml-roundtrip-validator v0.0.0-20201213122252-bcd7e1b9601e
	github.com/mattn/go-sqlite3 v1.14.22
	github.com/micromdm/micromdm v1.9.0
	github.com/micromdm/nanolib v0.2.0
	github.com/micromdm/plist v0.2.1
	github.com/mna/redisc v1.3.2
	github.com/ngrok/sqlmw v0.0.0-20211220175533-9d16fdc47b31
	github.com/nukosuke/go-zendesk v0.13.1
	github.com/open-policy-agent/opa v1.4.2
	github.com/oschwald/geoip2-golang v1.8.0
	github.com/osquery/osquery-go v0.0.0-20231130195733-61ac79279aaa
	github.com/pandatix/nvdapi v0.6.4
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/prometheus/client_golang v1.21.1
	github.com/rs/zerolog v1.34.0
	github.com/russellhaering/goxmldsig v1.2.0
	github.com/saferwall/pe v1.5.7
	github.com/sassoftware/relic/v8 v8.2.0
	github.com/shirou/gopsutil/v3 v3.24.5
	github.com/smallstep/pkcs7 v0.0.0-20240723090913-5e2c6a136dfa
	github.com/smallstep/scep v0.0.0-20240214080410-892e41795b99
	github.com/spf13/cast v1.7.1
	github.com/spf13/cobra v1.9.1
	github.com/spf13/viper v1.20.1
	github.com/stretchr/testify v1.10.0
	github.com/throttled/throttled/v2 v2.8.0
	github.com/ulikunitz/xz v0.5.14
	github.com/xi2/xz v0.0.0-20171230120015-48954b6210f8
	go.elastic.co/apm/module/apmgorilla/v2 v2.6.2
	go.elastic.co/apm/v2 v2.7.0
	go.etcd.io/bbolt v1.3.10
	go.opentelemetry.io/contrib/instrumentation/github.com/gorilla/mux/otelmux v0.56.0
	go.opentelemetry.io/otel v1.37.0
	golang.org/x/crypto v0.45.0
	golang.org/x/exp v0.0.0-20240719175910-8a7402abbf56
	golang.org/x/net v0.47.0
	golang.org/x/oauth2 v0.32.0
	golang.org/x/sync v0.18.0
	golang.org/x/sys v0.38.0
	golang.org/x/text v0.31.0
	golang.org/x/tools v0.38.0
	google.golang.org/api v0.215.0
	google.golang.org/grpc v1.75.0
	gopkg.in/guregu/null.v3 v3.5.0
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
	gopkg.in/yaml.v2 v2.4.0
	howett.net/plist v1.0.1
)

require (
	cloud.google.com/go v0.116.0 // indirect
	cloud.google.com/go/auth v0.13.0 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.2.6 // indirect
	cloud.google.com/go/compute/metadata v0.7.0 // indirect
	cloud.google.com/go/iam v1.2.2 // indirect
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/BurntSushi/toml v1.5.0 // indirect
	github.com/agnivade/levenshtein v1.2.1 // indirect
	github.com/apache/thrift v0.18.1 // indirect
	github.com/armon/go-radix v1.0.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/edsrzf/mmap-go v1.1.0 // indirect
	github.com/elastic/go-sysinfo v1.11.2 // indirect
	github.com/elastic/go-windows v1.0.1 // indirect
	github.com/fatih/structs v1.1.0 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/fsnotify/fsnotify v1.8.0 // indirect
	github.com/garyburd/go-oauth v0.0.0-20180319155456-bca2e7f09a17 // indirect
	github.com/go-ini/ini v1.67.0 // indirect
	github.com/go-logfmt/logfmt v0.5.1 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/go-viper/mapstructure/v2 v2.4.0 // indirect
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/go-querystring v1.1.0 // indirect
	github.com/google/s2a-go v0.1.8 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.4 // indirect
	github.com/googleapis/gax-go/v2 v2.14.1 // indirect
	github.com/gorilla/schema v1.4.1 // indirect
	github.com/groob/plist v0.0.0-20220217120414-63fa881b19a5 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/joeshaw/multierror v0.0.0-20140124173710-69b34d4ec901 // indirect
	github.com/jonboulle/clockwork v0.2.2 // indirect
	github.com/kevinburke/go-bindata v3.24.0+incompatible // indirect
	github.com/kolide/kit v0.0.0-20221107170827-fb85e3d59eab // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/oschwald/maxminddb-golang v1.10.0 // indirect
	github.com/pelletier/go-toml/v2 v2.2.3 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/power-devops/perfstat v0.0.0-20210106213030-5aafc221ea8c // indirect
	github.com/prometheus/client_model v0.6.1 // indirect
	github.com/prometheus/common v0.62.0 // indirect
	github.com/prometheus/procfs v0.15.1 // indirect
	github.com/quasilyte/go-ruleguard/dsl v0.3.22 // indirect
	github.com/rcrowley/go-metrics v0.0.0-20200313005456-10cdbea86bc0 // indirect
	github.com/sagikazarmark/locafero v0.7.0 // indirect
	github.com/secDre4mer/pkcs7 v0.0.0-20240322103146-665324a4461d // indirect
	github.com/shoenig/go-m1cpu v0.1.6 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/sourcegraph/conc v0.3.0 // indirect
	github.com/spf13/afero v1.12.0 // indirect
	github.com/spf13/pflag v1.0.6 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/tchap/go-patricia/v2 v2.3.2 // indirect
	github.com/tklauser/go-sysconf v0.3.12 // indirect
	github.com/tklauser/numcpus v0.6.1 // indirect
	github.com/trivago/tgo v1.0.7 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20190905194746-02993c407bfb // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/yashtewari/glob-intersection v0.2.0 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	go.elastic.co/apm/module/apmhttp/v2 v2.7.1-0.20250407084155-22ab1be21948 // indirect
	go.elastic.co/fastjson v1.1.0 // indirect
	go.mozilla.org/pkcs7 v0.0.0-20210826202110-33d05740a352 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.54.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.60.0 // indirect
	go.opentelemetry.io/otel/metric v1.37.0 // indirect
	go.opentelemetry.io/otel/sdk v1.37.0 // indirect
	go.opentelemetry.io/otel/trace v1.37.0 // indirect
	go.uber.org/multierr v1.10.0 // indirect
	golang.org/x/mod v0.29.0 // indirect
	golang.org/x/time v0.11.0 // indirect
	google.golang.org/genproto v0.0.0-20241118233622-e639e219e697 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20250707201910-8d1bb00bc6a7 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250818200422-3122310a409c // indirect
	google.golang.org/protobuf v1.36.8 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	sigs.k8s.io/yaml v1.4.0 // indirect
)

tool (
	github.com/kevinburke/go-bindata
	github.com/quasilyte/go-ruleguard/dsl
)

replace github.com/MobiusDM/mobius/shared => ../../common/shared
