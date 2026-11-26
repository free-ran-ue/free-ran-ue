# ApiConsoleGnbUeHandoverPostRequest


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**ip** | **string** | Source gNB API IP | [default to undefined]
**port** | **number** | Source gNB API port | [default to undefined]
**imsi** | **string** |  | [default to undefined]
**targetIp** | **string** | Target gNB API IP, the target must be the Xn peer of the source gNB | [default to undefined]
**targetPort** | **number** | Target gNB API port | [default to undefined]

## Example

```typescript
import { ApiConsoleGnbUeHandoverPostRequest } from './api';

const instance: ApiConsoleGnbUeHandoverPostRequest = {
    ip,
    port,
    imsi,
    targetIp,
    targetPort,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
