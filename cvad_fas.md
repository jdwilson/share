FAS 

```powershell
$store = Get-STFStoreService -VirtualPath [VirtualPath]
$auth = Get-STFAuthenticationService -StoreService $store
Set-STFStoreLaunchOptions -StoreService $store -VdaLogonDataProvider "FASLogonDataProvider" -FederatedAuthenticationServiceFailover $True
Set-STFClaimsFactoryNames -AuthenticationService $auth -ClaimsFactoryName "FASClaimsFactory"
```

## SAML SP Doc

https://docs.netscaler.com/en-us/citrix-adc/current-release/aaa-tm/authentication-methods/saml-authentication/azure-saml-idp.html
