# GNBApi

All URIs are relative to *http://127.0.0.1:40104*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**apiConsoleGnbInfoPost**](#apiconsolegnbinfopost) | **POST** /api/console/gnb/info | Get gNB Info|
|[**apiConsoleGnbUeHandoverPost**](#apiconsolegnbuehandoverpost) | **POST** /api/console/gnb/ue/handover | Xn Handover UE|
|[**apiConsoleGnbUeNrdcPost**](#apiconsolegnbuenrdcpost) | **POST** /api/console/gnb/ue/nrdc | Modify UE NRDC Status|

# **apiConsoleGnbInfoPost**
> ApiConsoleGnbInfoPost200Response apiConsoleGnbInfoPost(apiConsoleGnbInfoPostRequest)

Get gNB information with specified IP and port

### Example

```typescript
import {
    GNBApi,
    Configuration,
    ApiConsoleGnbInfoPostRequest
} from './api';

const configuration = new Configuration();
const apiInstance = new GNBApi(configuration);

let apiConsoleGnbInfoPostRequest: ApiConsoleGnbInfoPostRequest; //

const { status, data } = await apiInstance.apiConsoleGnbInfoPost(
    apiConsoleGnbInfoPostRequest
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **apiConsoleGnbInfoPostRequest** | **ApiConsoleGnbInfoPostRequest**|  | |


### Return type

**ApiConsoleGnbInfoPost200Response**

### Authorization

[BearerAuth](../README.md#BearerAuth)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Get gNB info successful |  -  |
|**400** | Invalid request format |  -  |
|**401** | Authentication failed |  -  |
|**500** | Internal server error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **apiConsoleGnbUeHandoverPost**
> ApiConsoleGnbUeHandoverPost200Response apiConsoleGnbUeHandoverPost(apiConsoleGnbUeHandoverPostRequest)

Hand over a single connection UE from the source gNB to its Xn peer gNB

### Example

```typescript
import {
    GNBApi,
    Configuration,
    ApiConsoleGnbUeHandoverPostRequest
} from './api';

const configuration = new Configuration();
const apiInstance = new GNBApi(configuration);

let apiConsoleGnbUeHandoverPostRequest: ApiConsoleGnbUeHandoverPostRequest; //

const { status, data } = await apiInstance.apiConsoleGnbUeHandoverPost(
    apiConsoleGnbUeHandoverPostRequest
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **apiConsoleGnbUeHandoverPostRequest** | **ApiConsoleGnbUeHandoverPostRequest**|  | |


### Return type

**ApiConsoleGnbUeHandoverPost200Response**

### Authorization

[BearerAuth](../README.md#BearerAuth)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Handover successful |  -  |
|**400** | Invalid request, UE in NRDC, or target gNB is not the Xn peer of the source gNB |  -  |
|**401** | Authentication failed |  -  |
|**404** | UE not found |  -  |
|**409** | UE is already in a handover |  -  |
|**500** | Handover failed |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **apiConsoleGnbUeNrdcPost**
> ApiConsoleGnbUeNrdcPost200Response apiConsoleGnbUeNrdcPost(apiConsoleGnbUeNrdcPostRequest)

Modify the NRDC status of a specific UE

### Example

```typescript
import {
    GNBApi,
    Configuration,
    ApiConsoleGnbUeNrdcPostRequest
} from './api';

const configuration = new Configuration();
const apiInstance = new GNBApi(configuration);

let apiConsoleGnbUeNrdcPostRequest: ApiConsoleGnbUeNrdcPostRequest; //

const { status, data } = await apiInstance.apiConsoleGnbUeNrdcPost(
    apiConsoleGnbUeNrdcPostRequest
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **apiConsoleGnbUeNrdcPostRequest** | **ApiConsoleGnbUeNrdcPostRequest**|  | |


### Return type

**ApiConsoleGnbUeNrdcPost200Response**

### Authorization

[BearerAuth](../README.md#BearerAuth)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | NRDC modification successful |  -  |
|**400** | Invalid request format |  -  |
|**401** | Authentication failed |  -  |
|**404** | UE not found |  -  |
|**500** | Internal server error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

