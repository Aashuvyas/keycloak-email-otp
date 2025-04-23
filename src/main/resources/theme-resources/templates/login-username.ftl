<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=true; section>

<div id="kc-form">
    <div id="kc-form-wrapper">
        <form id="kc-form-login" onsubmit="login.disabled = true; return true;" action="${url.loginAction}" method="post">
            <div class="${properties.kcFormGroupClass!}">
                <label for="username" class="${properties.kcLabelClass!}">${msg("username")}</label>
                <input tabindex="1" id="username" class="${properties.kcInputClass!}" name="username" value="${(login.username!'')}" type="text" autofocus autocomplete="off"/>
            </div>

            <div class="${properties.kcFormGroupClass!} ${properties.kcFormSettingClass!}">
                <div id="kc-form-buttons" class="${properties.kcFormButtonsClass!}">
                    <input tabindex="2" class="${properties.kcButtonClass!}" name="login" id="kc-login" type="submit" value="${msg("next")}"/>
                </div>
            </div>
        </form>
    </div>
</div>

</@layout.registrationLayout>
