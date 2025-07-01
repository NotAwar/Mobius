### Echo Webhook

A tiny web server you can use as a webhook callback for the MDM migration [end user workflow](https://mobiusmdm.com/docs/using-mobius/mdm-migration-guide#end-user-workflow)

This server won't do an actual unenrollment, but instead will print to stdout whatever information it gets from the Mobius server.

This is useful for testing and local development.

#### Usage

1. Start the webserver with:

```
go run tools/mdm/migration/echo/main.go
```

4. Configure Mobius to send a webhook to your web server.
