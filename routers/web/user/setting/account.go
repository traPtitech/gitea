// Copyright 2014 The Gogs Authors. All rights reserved.
// Copyright 2018 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package setting

import (
	"errors"
	"net/http"
	"time"

	"code.gitea.io/gitea/models"
	user_model "code.gitea.io/gitea/models/user"
	"code.gitea.io/gitea/modules/auth/password"
	"code.gitea.io/gitea/modules/base"
	"code.gitea.io/gitea/modules/log"
	"code.gitea.io/gitea/modules/optional"
	"code.gitea.io/gitea/modules/setting"
	"code.gitea.io/gitea/modules/web"
	"code.gitea.io/gitea/services/auth"
	"code.gitea.io/gitea/services/auth/source/db"
	"code.gitea.io/gitea/services/auth/source/smtp"
	"code.gitea.io/gitea/services/context"
	"code.gitea.io/gitea/services/forms"
	"code.gitea.io/gitea/services/user"
)

const (
	tplSettingsAccount base.TplName = "user/settings/account"
)

// Account renders change user's password, user's email and user suicide page
func Account(ctx *context.Context) {
	ctx.Data["Title"] = ctx.Tr("settings.account")
	ctx.Data["PageIsSettingsAccount"] = true
	ctx.Data["Email"] = ctx.Doer.Email
	ctx.Data["EnableNotifyMail"] = setting.Service.EnableNotifyMail

	loadAccountData(ctx)

	ctx.HTML(http.StatusOK, tplSettingsAccount)
}

// AccountPost response for change user's password
func AccountPost(ctx *context.Context) {
	form := web.GetForm(ctx).(*forms.ChangePasswordForm)
	ctx.Data["Title"] = ctx.Tr("settings")
	ctx.Data["PageIsSettingsAccount"] = true

	if ctx.HasError() {
		loadAccountData(ctx)

		ctx.HTML(http.StatusOK, tplSettingsAccount)
		return
	}

	if ctx.Doer.IsPasswordSet() && !ctx.Doer.ValidatePassword(form.OldPassword) {
		ctx.Flash.Error(ctx.Tr("settings.password_incorrect"))
	} else if form.Password != form.Retype {
		ctx.Flash.Error(ctx.Tr("form.password_not_match"))
	} else {
		opts := &user.UpdateAuthOptions{
			Password:           optional.Some(form.Password),
			MustChangePassword: optional.Some(false),
		}
		if err := user.UpdateAuth(ctx, ctx.Doer, opts); err != nil {
			switch {
			case errors.Is(err, password.ErrMinLength):
				ctx.Flash.Error(ctx.Tr("auth.password_too_short", setting.MinPasswordLength))
			case errors.Is(err, password.ErrComplexity):
				ctx.Flash.Error(password.BuildComplexityError(ctx.Locale))
			case errors.Is(err, password.ErrIsPwned):
				ctx.Flash.Error(ctx.Tr("auth.password_pwned"))
			case password.IsErrIsPwnedRequest(err):
				ctx.Flash.Error(ctx.Tr("auth.password_pwned_err"))
			default:
				ctx.ServerError("UpdateAuth", err)
				return
			}
		} else {
			ctx.Flash.Success(ctx.Tr("settings.change_password_success"))
		}
	}

	ctx.Redirect(setting.AppSubURL + "/user/settings/account")
}

// EmailPost response for change user's email
func EmailPost(ctx *context.Context) {
	ctx.Data["Title"] = ctx.Tr("settings")
	ctx.Data["PageIsSettingsAccount"] = true

	// Set Email Notification Preference
	if ctx.FormString("_method") == "NOTIFICATION" {
		preference := ctx.FormString("preference")
		if !(preference == user_model.EmailNotificationsEnabled ||
			preference == user_model.EmailNotificationsOnMention ||
			preference == user_model.EmailNotificationsDisabled ||
			preference == user_model.EmailNotificationsAndYourOwn) {
			log.Error("Email notifications preference change returned unrecognized option %s: %s", preference, ctx.Doer.Name)
			ctx.ServerError("SetEmailPreference", errors.New("option unrecognized"))
			return
		}
		opts := &user.UpdateOptions{
			EmailNotificationsPreference: optional.Some(preference),
		}
		if err := user.UpdateUser(ctx, ctx.Doer, opts); err != nil {
			log.Error("Set Email Notifications failed: %v", err)
			ctx.ServerError("UpdateUser", err)
			return
		}
		log.Trace("Email notifications preference made %s: %s", preference, ctx.Doer.Name)
		ctx.Flash.Success(ctx.Tr("settings.email_preference_set_success"))
		ctx.Redirect(setting.AppSubURL + "/user/settings/account")
		return
	}

	if ctx.HasError() {
		loadAccountData(ctx)

		ctx.HTML(http.StatusOK, tplSettingsAccount)
		return
	}
}

// DeleteEmail response for delete user's email
func DeleteEmail(ctx *context.Context) {
	email, err := user_model.GetEmailAddressByID(ctx, ctx.Doer.ID, ctx.FormInt64("id"))
	if err != nil || email == nil {
		ctx.ServerError("GetEmailAddressByID", err)
		return
	}

	if err := user.DeleteEmailAddresses(ctx, ctx.Doer, []string{email.Email}); err != nil {
		ctx.ServerError("DeleteEmailAddresses", err)
		return
	}
	log.Trace("Email address deleted: %s", ctx.Doer.Name)

	ctx.Flash.Success(ctx.Tr("settings.email_deletion_success"))
	ctx.JSONRedirect(setting.AppSubURL + "/user/settings/account")
}

// DeleteAccount render user suicide page and response for delete user himself
func DeleteAccount(ctx *context.Context) {
	if user_model.IsFeatureDisabledWithLoginType(ctx.Doer, setting.UserFeatureDeletion) {
		ctx.Error(http.StatusNotFound)
		return
	}

	ctx.Data["Title"] = ctx.Tr("settings")
	ctx.Data["PageIsSettingsAccount"] = true

	if _, _, err := auth.UserSignIn(ctx, ctx.Doer.Name, ctx.FormString("password")); err != nil {
		switch {
		case user_model.IsErrUserNotExist(err):
			loadAccountData(ctx)

			ctx.RenderWithErr(ctx.Tr("form.user_not_exist"), tplSettingsAccount, nil)
		case errors.Is(err, smtp.ErrUnsupportedLoginType):
			loadAccountData(ctx)

			ctx.RenderWithErr(ctx.Tr("form.unsupported_login_type"), tplSettingsAccount, nil)
		case errors.As(err, &db.ErrUserPasswordNotSet{}):
			loadAccountData(ctx)

			ctx.RenderWithErr(ctx.Tr("form.unset_password"), tplSettingsAccount, nil)
		case errors.As(err, &db.ErrUserPasswordInvalid{}):
			loadAccountData(ctx)

			ctx.RenderWithErr(ctx.Tr("form.enterred_invalid_password"), tplSettingsAccount, nil)
		default:
			ctx.ServerError("UserSignIn", err)
		}
		return
	}

	// admin should not delete themself
	if ctx.Doer.IsAdmin {
		ctx.Flash.Error(ctx.Tr("form.admin_cannot_delete_self"))
		ctx.Redirect(setting.AppSubURL + "/user/settings/account")
		return
	}

	if err := user.DeleteUser(ctx, ctx.Doer, false); err != nil {
		switch {
		case models.IsErrUserOwnRepos(err):
			ctx.Flash.Error(ctx.Tr("form.still_own_repo"))
			ctx.Redirect(setting.AppSubURL + "/user/settings/account")
		case models.IsErrUserHasOrgs(err):
			ctx.Flash.Error(ctx.Tr("form.still_has_org"))
			ctx.Redirect(setting.AppSubURL + "/user/settings/account")
		case models.IsErrUserOwnPackages(err):
			ctx.Flash.Error(ctx.Tr("form.still_own_packages"))
			ctx.Redirect(setting.AppSubURL + "/user/settings/account")
		case models.IsErrDeleteLastAdminUser(err):
			ctx.Flash.Error(ctx.Tr("auth.last_admin"))
			ctx.Redirect(setting.AppSubURL + "/user/settings/account")
		default:
			ctx.ServerError("DeleteUser", err)
		}
	} else {
		log.Trace("Account deleted: %s", ctx.Doer.Name)
		ctx.Redirect(setting.AppSubURL + "/")
	}
}

func loadAccountData(ctx *context.Context) {
	emlist, err := user_model.GetEmailAddresses(ctx, ctx.Doer.ID)
	if err != nil {
		ctx.ServerError("GetEmailAddresses", err)
		return
	}
	type UserEmail struct {
		user_model.EmailAddress
		CanBePrimary bool
	}
	pendingActivation := ctx.Cache.IsExist("MailResendLimit_" + ctx.Doer.LowerName)
	emails := make([]*UserEmail, len(emlist))
	for i, em := range emlist {
		var email UserEmail
		email.EmailAddress = *em
		email.CanBePrimary = em.IsActivated
		emails[i] = &email
	}
	ctx.Data["Emails"] = emails
	ctx.Data["EmailNotificationsPreference"] = ctx.Doer.EmailNotificationsPreference
	ctx.Data["ActivationsPending"] = pendingActivation
	ctx.Data["CanAddEmails"] = !pendingActivation || !setting.Service.RegisterEmailConfirm
	ctx.Data["UserDisabledFeatures"] = user_model.DisabledFeaturesWithLoginType(ctx.Doer)

	if setting.Service.UserDeleteWithCommentsMaxTime != 0 {
		ctx.Data["UserDeleteWithCommentsMaxTime"] = setting.Service.UserDeleteWithCommentsMaxTime.String()
		ctx.Data["UserDeleteWithComments"] = ctx.Doer.CreatedUnix.AsTime().Add(setting.Service.UserDeleteWithCommentsMaxTime).After(time.Now())
	}
}
