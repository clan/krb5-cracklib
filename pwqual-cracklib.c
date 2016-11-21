/**
 * @see http://web.mit.edu/Kerberos/krb5-latest/doc/plugindev/pwqual.html
 *
 * @todo add more check, see `man pam_cracklib`
 */
#include <ctype.h>
#include <crack.h>
#include <string.h>
#include <krb5/pwqual_plugin.h>


#define unused_var(x)      ((x) = (x))

/*
 * can't be a palindrome
 */
static int palindrome(const char *str)
{
    size_t i, j;

    i = strlen(str);

    for(j = 0; j < i; j++) {
        if (str[i - j - 1 ] != str[j]) {
            return 0;
        }
    }

    return 1;
}

static char *str_lower(char *str)
{
    char *cp;

    if (!str)
        return NULL;

    for (cp = str; *cp; cp++) {
        *cp = (char)tolower(*cp);
    }

    return str;
}

static const char *
pwqual_check(const char *username, const char *password)
{
    char *newmono = NULL;
    char *usermono = NULL;
    const char *res = NULL;

  #ifdef HAVE_FascistCheckUser
    res = FascistCheckUser(password, NULL, username, NULL);
  #else
    res = FascistCheck(password, NULL);
  #endif

    if (res)
        return res;

    do {
        newmono = str_lower(strdup(password));
        if (!newmono) {
            res = "memory allocation error";
            break;
        }

        usermono = str_lower(strdup(username));
        if (!usermono) {
            res = "memory allocation error";
            break;
        }

        if (palindrome(newmono)) {
            res = "is a plaindrome";
            break;
        }
    } while(0);

    if (newmono) {
        memset(newmono, 0, strlen(newmono));
        free(newmono);
    }
    if (usermono) {
        memset(usermono, 0, strlen(usermono));
        free(usermono);
    }

    return res;
}

#ifdef __MAIN__

int main(void)
{
    size_t i;
    const char *res = NULL, *user, *pass;

    const char *users[][2] = {
        {"liuzx", "123456"},
        {"liuzx", "aMirAlbblAriMa"}
    };

    for (i = 0; i < sizeof(users)/(2 * sizeof(const char *)); i++) {
        user = users[i][0];
        pass = users[i][1];
        res = pwqual_check(user, pass);
        if (res) {
            printf("[u:%s|p:%s]: %s\n", user, pass, res);
        }
    }

    return 0;
}

#else

static krb5_error_code
pwqual_cracklib_check(krb5_context context, krb5_pwqual_moddata data,
              const char *password, const char *policy_name,
              krb5_principal princ, const char **languages)
{
    krb5_error_code ret;
    const char *res = NULL;
    const char *username = NULL;

    unused_var(data);
    unused_var(languages);

    /* no check for principals w/o password policy. */
    if (policy_name == NULL)
        return 0;

    if (princ->data && krb5_princ_size(context, princ) > 0) {
        username = princ->data[0].data;
    } else {
        username = "";
    }

    res = pwqual_check(username, password);
    if (res) {
        krb5_set_error_message(context, KADM5_PASS_Q_GENERIC, "%s", res);
        ret = KADM5_PASS_Q_GENERIC;
    } else {
        ret = 0;
    }

    return ret;
}

krb5_error_code __attribute__((__visibility__("default")))
pwqual_cracklib_initvt(krb5_context context, int maj_ver, int min_ver,
                       krb5_plugin_vtable vtable)
{
    struct krb5_pwqual_vtable_st *vt;

    unused_var(context);
    unused_var(min_ver);

    if (maj_ver != 1)
        return KRB5_PLUGIN_VER_NOTSUPP;

    vt = (struct krb5_pwqual_vtable_st *)vtable;
    memset(vt, 0, sizeof *vt);

    vt->name = "cracklib";
    vt->check = pwqual_cracklib_check;

    return 0;
}

#endif
