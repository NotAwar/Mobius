module github.com/MobiusDM/mobius/server/api

go 1.25.3

require (
	cloud.google.com/go/pubsub v1.50.1
	github.com/Masterminds/semver/v3 v3.4.0
	github.com/MobiusDM/mobius/shared v0.0.0-00010101000000-000000000000
	github.com/RobotsAndPencils/buford v0.14.0
	github.com/VividCortex/mysqlerr v0.0.0-20170204212430-6c6b55f8796f
	github.com/WatchBeam/clock v0.0.0-20170901150240-b08e6b4da7ea
	github.com/XSAM/otelsql v0.40.0
	github.com/andygrunwald/go-jira v1.17.0
	github.com/apex/log v1.9.0
	github.com/aws/aws-sdk-go v1.55.8
	github.com/aws/aws-sdk-go-v2/feature/cloudfront/sign v1.9.13
	github.com/beevik/etree v1.6.0
	github.com/blakesmith/ar v0.0.0-20190502131153-809d4375e1fb
	github.com/boltdb/bolt v1.3.1
	github.com/cavaliergopher/rpm v1.3.0
	github.com/cenkalti/backoff v2.2.1+incompatible
	github.com/cenkalti/backoff/v4 v4.3.0
	github.com/docker/go-units v0.5.0
	github.com/doug-martin/goqu/v9 v9.19.0
	github.com/facebookincubator/flog v0.0.0-20190930132826-d2511d0ce33c
	github.com/fatih/color v1.18.0
	github.com/getsentry/sentry-go v0.38.0
	github.com/ghodss/yaml v1.0.0
	github.com/github/smimesign v0.2.0
	github.com/go-json-experiment/json v0.0.0-20250517221953-25912455fbc8
	github.com/go-kit/kit v0.13.0
	github.com/go-kit/log v0.2.1
	github.com/go-sql-driver/mysql v1.9.3
	github.com/gocarina/gocsv v0.0.0-20220310154401-d4df709ca055
	github.com/golang-jwt/jwt/v4 v4.5.2
	github.com/gomodule/oauth1 v0.2.0
	github.com/gomodule/redigo v1.9.3
	github.com/google/go-cmp v0.7.0
	github.com/google/go-github/v37 v37.0.0
	github.com/google/uuid v1.6.0
	github.com/gorilla/mux v1.8.1
	github.com/gorilla/websocket v1.5.3
	github.com/groob/finalizer v0.0.0-20170707115354-4c2ed49aabda
	github.com/hashicorp/go-multierror v1.1.1
	github.com/igm/sockjs-go/v3 v3.0.3
	github.com/jmoiron/sqlx v1.4.0
	github.com/klauspost/compress v1.18.1
	github.com/kolide/launcher v1.29.0
	github.com/lib/pq v1.10.9
	github.com/mattermost/xml-roundtrip-validator v0.1.0
	github.com/mattn/go-sqlite3 v1.14.32
	github.com/micromdm/micromdm v1.13.1
	github.com/micromdm/nanolib v0.5.0
	github.com/micromdm/plist v0.2.1
	github.com/mna/redisc v1.4.0
	github.com/ngrok/sqlmw v0.0.0-20211220175533-9d16fdc47b31
	github.com/nukosuke/go-zendesk v0.18.0
	github.com/open-policy-agent/opa v1.10.1
	github.com/oschwald/geoip2-golang v1.13.0
	github.com/osquery/osquery-go v0.0.0-20250131154556-629f995b6947
	github.com/pandatix/nvdapi v0.6.5
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/prometheus/client_golang v1.23.2
	github.com/rs/zerolog v1.34.0
	github.com/russellhaering/goxmldsig v1.5.0
	github.com/saferwall/pe v1.5.7
	github.com/sassoftware/relic/v8 v8.2.0
	github.com/shirou/gopsutil/v3 v3.24.5
	github.com/smallstep/pkcs7 v0.2.1
	github.com/smallstep/scep v0.0.0-20241223071629-a37a330173bc
	github.com/spf13/cast v1.10.0
	github.com/spf13/cobra v1.10.1
	github.com/spf13/viper v1.21.0
	github.com/stretchr/testify v1.11.1
	github.com/throttled/throttled/v2 v2.15.0
	github.com/ulikunitz/xz v0.5.15
	github.com/xi2/xz v0.0.0-20171230120015-48954b6210f8
	go.elastic.co/apm/module/apmgorilla/v2 v2.7.1
	go.elastic.co/apm/v2 v2.7.1
	go.etcd.io/bbolt v1.4.0
	go.opentelemetry.io/contrib/instrumentation/github.com/gorilla/mux/otelmux v0.63.0
	go.opentelemetry.io/otel v1.38.0
	golang.org/x/crypto v0.44.0
	golang.org/x/exp v0.0.0-20250408133849-7e4ce0ab07d0
	golang.org/x/net v0.46.0
	golang.org/x/oauth2 v0.33.0
	golang.org/x/sync v0.18.0
	golang.org/x/sys v0.38.0
	golang.org/x/text v0.31.0
	golang.org/x/tools v0.38.0
	google.golang.org/api v0.247.0
	google.golang.org/grpc v1.75.1
	gopkg.in/guregu/null.v3 v3.5.0
	gopkg.in/natefinch/lumberjack.v2 v2.2.1
	gopkg.in/yaml.v2 v2.4.0
	howett.net/plist v1.0.1
)

require (
	cloud.google.com/go v0.121.6 // indirect
	cloud.google.com/go/auth v0.16.4 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.2.8 // indirect
	cloud.google.com/go/compute/metadata v0.8.0 // indirect
	cloud.google.com/go/iam v1.5.2 // indirect
	cloud.google.com/go/pubsub/v2 v2.0.0 // indirect
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/agnivade/levenshtein v1.2.1 // indirect
	github.com/apache/thrift v0.20.0 // indirect
	github.com/armon/go-radix v1.0.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	github.com/edsrzf/mmap-go v1.1.0 // indirect
	github.com/elastic/go-sysinfo v1.11.2 // indirect
	github.com/elastic/go-windows v1.0.1 // indirect
	github.com/fatih/structs v1.1.0 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/garyburd/go-oauth v0.0.0-20180319155456-bca2e7f09a17 // indirect
	github.com/go-ini/ini v1.67.0 // indirect
	github.com/go-logfmt/logfmt v0.5.1 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/go-viper/mapstructure/v2 v2.4.0 // indirect
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/goccy/go-json v0.10.5 // indirect
	github.com/google/go-querystring v1.1.0 // indirect
	github.com/google/s2a-go v0.1.9 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.6 // indirect
	github.com/googleapis/gax-go/v2 v2.15.0 // indirect
	github.com/gorilla/schema v1.4.1 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/joeshaw/multierror v0.0.0-20140124173710-69b34d4ec901 // indirect
	github.com/jonboulle/clockwork v0.5.0 // indirect
	github.com/kevinburke/go-bindata v3.24.0+incompatible // indirect
	github.com/kolide/kit v0.0.0-20250324140823-36d978ef488c // indirect
	github.com/lestrrat-go/blackmagic v1.0.4 // indirect
	github.com/lestrrat-go/dsig v1.0.0 // indirect
	github.com/lestrrat-go/dsig-secp256k1 v1.0.0 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/httprc/v3 v3.0.1 // indirect
	github.com/lestrrat-go/jwx/v3 v3.0.11 // indirect
	github.com/lestrrat-go/option v1.0.1 // indirect
	github.com/lestrrat-go/option/v2 v2.0.0 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/oschwald/maxminddb-golang v1.13.0 // indirect
	github.com/pelletier/go-toml/v2 v2.2.4 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/power-devops/perfstat v0.0.0-20240221224432-82ca36839d55 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.66.1 // indirect
	github.com/prometheus/procfs v0.17.0 // indirect
	github.com/quasilyte/go-ruleguard/dsl v0.3.22 // indirect
	github.com/rcrowley/go-metrics v0.0.0-20250401214520-65e299d6c5c9 // indirect
	github.com/sagikazarmark/locafero v0.11.0 // indirect
	github.com/samber/lo v1.38.1 // indirect
	github.com/samber/slog-multi v1.0.2 // indirect
	github.com/secDre4mer/pkcs7 v0.0.0-20240322103146-665324a4461d // indirect
	github.com/segmentio/asm v1.2.0 // indirect
	github.com/shoenig/go-m1cpu v0.1.6 // indirect
	github.com/sirupsen/logrus v1.9.4-0.20230606125235-dd1b4c2e81af // indirect
	github.com/sourcegraph/conc v0.3.1-0.20240121214520-5f936abd7ae8 // indirect
	github.com/spf13/afero v1.15.0 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/tchap/go-patricia/v2 v2.3.3 // indirect
	github.com/tklauser/go-sysconf v0.3.15 // indirect
	github.com/tklauser/numcpus v0.10.0 // indirect
	github.com/trivago/tgo v1.0.7 // indirect
	github.com/valyala/fastjson v1.6.4 // indirect
	github.com/vektah/gqlparser/v2 v2.5.30 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20190905194746-02993c407bfb // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/yashtewari/glob-intersection v0.2.0 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	go.elastic.co/apm/module/apmhttp/v2 v2.7.1 // indirect
	go.elastic.co/fastjson v1.5.1 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.61.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.63.0 // indirect
	go.opentelemetry.io/otel/metric v1.38.0 // indirect
	go.opentelemetry.io/otel/sdk v1.38.0 // indirect
	go.opentelemetry.io/otel/trace v1.38.0 // indirect
	go.yaml.in/yaml/v2 v2.4.2 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	golang.org/x/mod v0.29.0 // indirect
	golang.org/x/time v0.13.0 // indirect
	google.golang.org/genproto v0.0.0-20250603155806-513f23925822 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20250825161204-c5933d9347a5 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250825161204-c5933d9347a5 // indirect
	google.golang.org/protobuf v1.36.9 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	sigs.k8s.io/yaml v1.6.0 // indirect
)

tool (
	github.com/kevinburke/go-bindata
	github.com/quasilyte/go-ruleguard/dsl
)

replace github.com/MobiusDM/mobius/shared => ../../common/shared
