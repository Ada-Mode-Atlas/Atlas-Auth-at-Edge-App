# Authorization with Lambda@Edge

Easily add OAuth2 flows to apply authorization to any content served through AWS Cloudfront.

Note: This application must be deployed in us-east-1. You can deploy instances of the app [here](https://us-east-1.console.aws.amazon.com/serverlessrepo/home?region=us-east-1#/published-applications/arn:aws:serverlessrepo:us-east-1:539182614893:applications~Atlas-Auth-at-Edge).

## Requirements

* OIDC dicsovery document url such as `.../.well-known/openid-configuration`
* Cloudfront distribution (for deployment of the application)

If the openid configuration is taked from a cognito userpool it must have a corresponding domain with a managed login UI.

## Resources

A deployed instance of the application creates the following resources:
* Auth Handler: A lambda function in a python runtime suitable to running on the edge and initiate oauth2 flows and coordinate sign-in, refresh or permit access
* Callback Handler: A lambda function in a python runtime suitable to running on the edge and respond to IdP auth code provision and collect tokens
* SSM Parameters: A set of parameters controlling the IdP including the client Id, Callback path & discovery document URL

## Integration

The deployed application will return the ARN of the two created lambda handlers, these can now be integrated into you Cloudfront distribution.

This may look like this:
* Add a lambda@edge integration to all user-request actions to each non-public behaviour
* Create a custom origin (named something like `auth-callback-origin`)
* Create a behaviour on path `/auth/callback` pointing to your custom origin (or matching whatver value was used for the callback stack parameter) with caching disabled
* Add a lambda@edge integration to this new bevahiour to use the callback handler

This will now enforce authentication on each configured behaviour.

## Limitations

This application is only suitable for a single App Client, multiple instances will need to be configured for additional client support.

## Updates

When integrating a lambda function on edge use must specify a versioned function ARN such as `arn:aws:lambda:us-east-1:{AccountId}:function:{StackName}-AuthorizeFunction-...:1`, hence if you deploy an updated instance of this application you will need to increment the ARN within the cloudfront behaviour integrations.

