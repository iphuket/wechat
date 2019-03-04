// Package platforms 参考 https://github.com/beautiful-you/anniversary/wechat/tree/master/util
package platforms

import (
	"encoding/json"
	"fmt"

	"github.com/iphuket/gowc/config"
	"github.com/iphuket/wechat/util"
)

// 接口信息
const (
	ComponentTokenURL = "https://api.weixin.qq.com/cgi-bin/component/api_component_token"
	PreAuthCodeURL    = "https://api.weixin.qq.com/cgi-bin/component/api_create_preauthcode?component_access_token=%s"
	// AuthURL           = "https://mp.weixin.qq.com/safe/bindcomponent?action=bindcomponent&auth_type=3&no_scan=1&component_appid=%s&pre_auth_code=%s&redirect_uri=%s&auth_type=xxx&biz_appid=xxxx#wechat_redirect"
	AuthURL                        = "https://mp.weixin.qq.com/cgi-bin/componentloginpage?component_appid=%s&pre_auth_code=%s&redirect_uri=%s&auth_type=3"
	AuthInfoURL                    = "https://api.weixin.qq.com/cgi-bin/component/api_query_auth?component_access_token=%s"
	RefresAuthorizerAccessTokenURL = "https://api.weixin.qq.com/cgi-bin/component/api_authorizer_token?component_access_token=%s"
	AuthorizerInfoURL              = "https://api.weixin.qq.com/cgi-bin/component/api_get_authorizer_info?component_access_token=%s"
)

// ResComponentAccessToken ComponentAccessToken
type ResComponentAccessToken struct {
	util.CommonError
	ComponentAccessToken string `json:"component_access_token"`
	ExpiresIn            int64  `json:"expires_in"`
}

// ResPreAuthCode 预授权码
type ResPreAuthCode struct {
	util.CommonError
	PreAuthCode string `json:"pre_auth_code"`
	ExpiresIn   int64  `json:"expires_in"`
}

// ComponentAccessToken // 获取第三方平台 component_access_token
func ComponentAccessToken(ComponentAppID, AppSecret, cvt string) (*ResComponentAccessToken, error) {
	var ca = new(config.Cache)

	// 获取第三方平台 component_access_token
	body, err := util.PostJSON(ComponentTokenURL, map[string]string{"component_appid": ComponentAppID, "component_appsecret": AppSecret, "component_verify_ticket": cvt})
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	resComponentAccessToken := new(ResComponentAccessToken)
	err = json.Unmarshal(body, &resComponentAccessToken)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	if resComponentAccessToken.ErrMsg != "" {
		err = fmt.Errorf("get access_token error : errcode=%v , errormsg=%v", resComponentAccessToken.ErrCode, resComponentAccessToken.ErrMsg)
		return resComponentAccessToken, err
	}
	err = ca.Set("ComponentAccessToken", resComponentAccessToken.ComponentAccessToken)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	return resComponentAccessToken, nil
}

// PreAuthCode 获取预授权码 pre_auth_code
func PreAuthCode(ComponentAppID, ComponentAccessToken string) (*ResPreAuthCode, error) {
	// 获取预授权码 pre_auth_code
	url := fmt.Sprintf(PreAuthCodeURL, ComponentAccessToken)
	body, err := util.PostJSON(url, map[string]string{"component_appid": ComponentAppID})
	if err != nil {
		return nil, err
	}
	resPreAuthCode := new(ResPreAuthCode)
	err = json.Unmarshal(body, &resPreAuthCode)
	if err != nil {
		return nil, err
	}
	if resPreAuthCode.ErrMsg != "" {
		err = fmt.Errorf("get auth_code error : errcode=%v , errormsg=%v", resPreAuthCode.ErrCode, resPreAuthCode.ErrMsg)
		return resPreAuthCode, err
	}
	return resPreAuthCode, nil
}

// ResAuthInfo 授权信息结构体
type ResAuthInfo struct {
	util.CommonError
	AuthorizationInfo ResAuthorizationInfo `json:"authorization_info"`
}

// ResAuthorizationInfo 授权信息结构体
type ResAuthorizationInfo struct {
	AuthorizerAppID        string        `json:"authorizer_appid"`
	AuthorizerAccessToken  string        `json:"authorizer_access_token"`
	ExpiresIn              int64         `json:"expires_in"`
	AuthorizerRefreshToken string        `json:"authorizer_refresh_token"`
	FuncInfo               []ResFuncInfo `json:"func_info"`
}

// ResFuncInfo 授权给开发者的权限集列表
type ResFuncInfo struct {
	FuncscopeCategory ResFuncscopeCategory `json:"funcscope_category"`
}

// ResFuncscopeCategory ...
type ResFuncscopeCategory struct {
	ID int64 `json:"id"`
}

// AuthBaseInfo 基础授权信息
func AuthBaseInfo(ComponentAppID, ComponentAccessToken, AuthCode string) (*ResAuthInfo, error) {
	// 授权信息 pre_auth_code
	url := fmt.Sprintf(AuthInfoURL, ComponentAccessToken)
	body, err := util.PostJSON(url, map[string]string{"component_appid": ComponentAppID, "authorization_code": AuthCode})
	if err != nil {
		return nil, err
	}
	resAuthInfo := new(ResAuthInfo)
	err = json.Unmarshal(body, &resAuthInfo)
	if err != nil {
		return nil, err
	}
	if resAuthInfo.ErrMsg != "" {
		err = fmt.Errorf("get auth_code error : errcode=%v , errormsg=%v", resAuthInfo.ErrCode, resAuthInfo.ErrMsg)
		return resAuthInfo, err
	}
	return resAuthInfo, nil
}

// ResRefresAuthorizerAccessToken 刷新令牌
type ResRefresAuthorizerAccessToken struct {
	util.CommonError
	AuthorizerAccessToken  string `json:"authorizer_access_token"`
	ExpiresIn              int64  `json:"expires_in"`
	AuthorizerRefreshToken string `json:"authorizer_refresh_token"`
}

// RefresAuthorizerAccessToken 刷新
func RefresAuthorizerAccessToken(ComponentAppID, ComponentAccessToken, AuthorizerAppID, AuthorizerRefreshToken string) (*ResRefresAuthorizerAccessToken, error) {
	url := fmt.Sprintf(RefresAuthorizerAccessTokenURL, ComponentAccessToken)
	body, err := util.PostJSON(url, map[string]string{"component_appid": ComponentAppID, "authorizer_appid": AuthorizerAppID, "authorizer_refresh_token": AuthorizerRefreshToken})
	if err != nil {
		return nil, err
	}
	resRefresAuthorizerAccessToken := new(ResRefresAuthorizerAccessToken)
	err = json.Unmarshal(body, &resRefresAuthorizerAccessToken)
	if err != nil {
		return nil, err
	}
	if resRefresAuthorizerAccessToken.ErrMsg != "" {
		err = fmt.Errorf("get auth_code error : errcode=%v , errormsg=%v", resRefresAuthorizerAccessToken.ErrCode, resRefresAuthorizerAccessToken.ErrMsg)
		return resRefresAuthorizerAccessToken, err
	}
	return resRefresAuthorizerAccessToken, nil
}

// ResAuthorizerInfo 授权的公众号信息
type ResAuthorizerInfo struct {
	util.CommonError
	JSONAuthorizerInfo JSONAuthorizerInfo `json:"authorizer_info"`
}

// JSONAuthorizerInfo ... 授权的公众号信息 JSON 结构体
type JSONAuthorizerInfo struct {
	NickName        string                     `json:"nick_name"`
	HeadImg         string                     `json:"head_img"`
	ServiceTypeInfo string                     `json:"service_type_info"`
	VerifyTypeInfo  string                     `json:"verify_type_info"`
	UserName        string                     `json:"user_name"`
	PrincipalName   string                     `json:"principal_name"`
	Alias           string                     `json:"alias"`
	QrcodeURL       string                     `json:"qrcode_url"`
	BusinessInfo    AuthorizerInfoBusinessInfo `json:"business_info"`
}

// AuthorizerInfoBusinessInfo ... 用以了解以下功能的开通状况（0代表未开通，1代表已开通）： open_store:是否开通微信门店功能 open_scan:是否开通微信扫商品功能 open_pay:是否开通微信支付功能 open_card:是否开通微信卡券功能 open_shake:是否开通微信摇一摇功能
type AuthorizerInfoBusinessInfo struct {
	OpenStore string `json:"open_store"`
	OpenScan  string `json:"open_scan"`
	OpenPay   string `json:"open_pay"`
	OpenCard  string `json:"open_card"`
	OpenShake string `json:"open_shake"`
}

// AuthorizerInfo 获取授权的公众号信息
func AuthorizerInfo(ComponentAppID, ComponentAccessToken, AuthorizerAppID string) (*ResAuthorizerInfo, error) {
	url := fmt.Sprintf(AuthorizerInfoURL, ComponentAccessToken)
	body, err := util.PostJSON(url, map[string]string{"component_appid": ComponentAppID, "authorizer_appid": AuthorizerAppID})
	if err != nil {
		return nil, err
	}
	resAuthorizerInfo := new(ResAuthorizerInfo)
	err = json.Unmarshal(body, &resAuthorizerInfo)
	if err != nil {
		return nil, err
	}
	if resAuthorizerInfo.ErrMsg != "" {
		err = fmt.Errorf("get auth_code error : errcode=%v , errormsg=%v", resAuthorizerInfo.ErrCode, resAuthorizerInfo.ErrMsg)
		return resAuthorizerInfo, err
	}
	return resAuthorizerInfo, nil
}
