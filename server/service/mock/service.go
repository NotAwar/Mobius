package mock

//go:generate go run ../../mock/mockimpl/impl.go -o service_osquery.go "s *TLSService" "mobius.OsqueryService"
//go:generate go run ../../mock/mockimpl/impl.go -o service_pusher_factory.go "s *APNSPushProviderFactory" "github.com/notawar/mobius/server/mdm/nanomdm/push.PushProviderFactory"
//go:generate go run ../../mock/mockimpl/impl.go -o service_push_provider.go "s *APNSPushProvider" "github.com/notawar/mobius/server/mdm/nanomdm/push.PushProvider"
