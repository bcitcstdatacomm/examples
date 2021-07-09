#include "echo.h"
#include <dc_network/server.h>
#include <dc_network/common.h>
#include <dc_application/command_line.h>
#include <dc_application/environment.h>
#include <dc_application/config.h>
#include <dc_application/defaults.h>
#include <dc_application/options.h>
#include <dc_util/dump.h>
#include <dc_util/streams.h>
#include <dc_util/types.h>
#include <dc_posix/netdb.h>
#include <dc_posix/signal.h>
#include <dc_posix/string.h>
#include <dc_posix/sys/socket.h>
#include <getopt.h>
#include <inttypes.h>


#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpadded"
struct application_settings
{
    struct dc_opt_settings opts;
    struct dc_setting_bool *verbose;
    struct dc_setting_string *hostname;
    struct dc_setting_regex *ip_version;
    struct dc_setting_uint16 *port;
    struct dc_setting_bool *reuse_address;
    struct addrinfo *result;
    int server_socket_fd;
};
#pragma GCC diagnostic pop


static struct dc_application_lifecycle *create_application_lifecycle(const struct dc_posix_env *env, struct dc_error *err);
static void destroy_application_lifecycle(const struct dc_posix_env *env, struct dc_application_lifecycle **plifecycle);
static struct dc_application_settings *create_settings(const struct dc_posix_env *env, struct dc_error *err);
static int destroy_settings(const struct dc_posix_env *env, struct dc_error *err, struct dc_application_settings **psettings);
static int run(const struct dc_posix_env *env, struct dc_error *err, struct dc_application_settings *settings);
static void signal_handler(int signnum);
static int do_create_settings(const struct dc_posix_env *env, struct dc_error *err, void *arg);
static int do_create_socket(const struct dc_posix_env *env, struct dc_error *err, void *arg);
static int do_set_sockopts(const struct dc_posix_env *env, struct dc_error *err, void *arg);
static int do_bind(const struct dc_posix_env *env, struct dc_error *err, void *arg);
static int do_listen(const struct dc_posix_env *env, struct dc_error *err, void *arg);
static int do_setup(const struct dc_posix_env *env, struct dc_error *err, void *arg);
static int do_accept(const struct dc_posix_env *env, struct dc_error *err, void *arg);
static int do_shutdown(const struct dc_posix_env *env, struct dc_error *err, void *arg);
static int do_destroy_settings(const struct dc_posix_env *env, struct dc_error *err, void *arg);
static void error_reporter(const struct dc_posix_env *env, const struct dc_error *err);
static void trace(const struct dc_posix_env *env, const char *file_name, const char *function_name, size_t line_number);
static void write_displayer(const struct dc_posix_env *env, struct dc_error *err, const uint8_t *data, size_t count, size_t file_position, void *arg);
static void read_displayer(const struct dc_posix_env *env, struct dc_error *err, const uint8_t *data, size_t count, size_t file_position, void *arg);


static volatile sig_atomic_t exit_signal = 0;


int main(int argc, char *argv[])
{
    struct dc_posix_env         env;
    struct dc_error             err;
    struct dc_application_info *info;
    int                         ret_val;
    struct sigaction            sa;

    dc_posix_env_init(&env, error_reporter);
    dc_error_init(&err);
    dc_memset(&env, &sa, 0, sizeof(sa));
    sa.sa_handler = &signal_handler;
    dc_sigaction(&env, &err, SIGINT , &sa, NULL);
    dc_sigaction(&env, &err, SIGTERM, &sa, NULL);

//    env.tracer = trace;
    info      = dc_application_info_create(&env, &err, "Test Application", NULL);
    ret_val   = dc_application_run(&env, &err, info, create_application_lifecycle, destroy_application_lifecycle,
                                   "~/.dcecho.conf",
                                   argc, argv);
    dc_application_info_destroy(&env, &info);
    dc_error_reset(&err);

    return ret_val;
}


static struct dc_application_lifecycle *create_application_lifecycle(const struct dc_posix_env *env, struct dc_error *err)
{
    struct dc_application_lifecycle *lifecycle;

    lifecycle = dc_application_lifecycle_create(env, err, create_settings, destroy_settings, run);
    dc_application_lifecycle_set_parse_command_line(env, lifecycle, dc_default_parse_command_line);
    dc_application_lifecycle_set_read_env_vars(env, lifecycle, dc_default_read_env_vars);
    dc_application_lifecycle_set_read_config(env, lifecycle, dc_default_load_config);
    dc_application_lifecycle_set_set_defaults(env, lifecycle, dc_default_set_defaults);

    return lifecycle;
}

static void destroy_application_lifecycle(const struct dc_posix_env *env, struct dc_application_lifecycle **plifecycle)
{
    DC_TRACE(env);
    dc_application_lifecycle_destroy(env, plifecycle);
}


static struct dc_application_settings *create_settings(const struct dc_posix_env *env, struct dc_error *err)
{
    static const bool            default_verbose  = false;
    static const char           *default_hostname = "localhost";
    static const char           *default_ip       = "IPv4";
    static const uint16_t        default_port     = DEFAULT_ECHO_PORT;
    static const bool            default_reuse    = false;
    struct application_settings *settings;

    settings = dc_malloc(env, err, sizeof(struct application_settings));

    if(settings == NULL)
    {
        return NULL;
    }

    settings->opts.parent.config_path = dc_setting_path_create(env, err);
    settings->verbose                 = dc_setting_bool_create(env, err);
    settings->hostname                = dc_setting_string_create(env, err);
    settings->ip_version              = dc_setting_regex_create(env, err, "^IPv[4|6]");
    settings->port                    = dc_setting_uint16_create(env, err);
    settings->reuse_address           = dc_setting_bool_create(env, err);

    struct options opts[] =
    {
        { (struct dc_setting *)settings->opts.parent.config_path, dc_options_set_path,   "config",   required_argument, 'c', "CONFIG",        dc_string_from_string, NULL,            dc_string_from_config, NULL             },
        { (struct dc_setting *)settings->verbose,                 dc_options_set_bool,   "verbose",  no_argument,       'v', "VERBOSE",       dc_flag_from_string,   "verbose",       dc_flag_from_config,   &default_verbose },
        { (struct dc_setting *)settings->hostname,                dc_options_set_string, "host",     required_argument, 'h', "HOST",          dc_string_from_string, "host",          dc_string_from_config, default_hostname },
        { (struct dc_setting *)settings->ip_version,              dc_options_set_regex,  "ip",       required_argument, 'i', "IP",            dc_string_from_string, "ip",            dc_string_from_config, default_ip       },
        { (struct dc_setting *)settings->port,                    dc_options_set_uint16, "port",     required_argument, 'p', "PORT",          dc_uint16_from_string, "port",          dc_uint16_from_config, &default_port    },
        { (struct dc_setting *)settings->reuse_address,           dc_options_set_bool,   "force",    no_argument,       'f', "REUSE_ADDRESS", dc_flag_from_string,   "reuse_address", dc_flag_from_config,   &default_reuse   },
    };

    // note the trick here - we use calloc and add 1 to ensure the last line is all 0/NULL
    settings->opts.opts = dc_calloc(env, err, (sizeof(opts) / sizeof(struct options)) + 1, sizeof(struct options));
    dc_memcpy(env, settings->opts.opts, opts, sizeof(opts));
    settings->opts.flags = "c:vh:i:p:f";
    settings->opts.env_prefix = "DC_ECHO_";

    return (struct dc_application_settings *)settings;
}

static int destroy_settings(const struct dc_posix_env *env, __attribute__ ((unused)) struct dc_error *err, struct dc_application_settings **psettings)
{
    struct application_settings *app_settings;

    app_settings = (struct application_settings *)*psettings;
    dc_setting_bool_destroy(env, &app_settings->verbose);
    dc_setting_string_destroy(env, &app_settings->hostname);
    dc_setting_uint16_destroy(env, &app_settings->port);
    dc_free(env, app_settings->opts.opts, app_settings->opts.opts_size);
    dc_free(env, app_settings, sizeof(struct application_settings));

    if(env->null_free)
    {
        *psettings = NULL;
    }

    return 0;
}


static struct dc_server_lifecycle *create_server_lifecycle(const struct dc_posix_env *env, struct dc_error *err)
{
    struct dc_server_lifecycle *lifecycle;

    lifecycle = dc_server_lifecycle_create(env, err);
    dc_server_lifecycle_set_create_settings(env, lifecycle, do_create_settings);
    dc_server_lifecycle_set_create_socket(env, lifecycle, do_create_socket);
    dc_server_lifecycle_set_set_sockopts(env, lifecycle, do_set_sockopts);
    dc_server_lifecycle_set_bind(env, lifecycle, do_bind);
    dc_server_lifecycle_set_listen(env, lifecycle, do_listen);
    dc_server_lifecycle_set_setup(env, lifecycle, do_setup);
    dc_server_lifecycle_set_accept(env, lifecycle, do_accept);
    dc_server_lifecycle_set_shutdown(env, lifecycle, do_shutdown);
    dc_server_lifecycle_set_destroy_settings(env, lifecycle, do_destroy_settings);

    return lifecycle;
}


static void destroy_server_lifecycle(const struct dc_posix_env *env, struct dc_server_lifecycle **plifecycle)
{
    DC_TRACE(env);
    dc_server_lifecycle_destroy(env, plifecycle);
}


static int run(const struct dc_posix_env *env, __attribute__ ((unused)) struct dc_error *err, struct dc_application_settings *settings)
{
    int ret_val;
    struct dc_server_info *info;

    info = dc_server_info_create(env, err, "Echo Server", NULL, settings);

    if(DC_HAS_NO_ERROR(err))
    {
        dc_server_run(env, err, info, create_server_lifecycle, destroy_server_lifecycle);
        dc_server_info_destroy(env, &info);
    }

    if(DC_HAS_NO_ERROR(err))
    {
        ret_val = 0;
    }
    else
    {
        ret_val = -1;
    }

    /*
    struct addrinfo *res;

    res = result;
    printf("Host: %s\n", hostname);

    while(res)
    {
        char addrstr[100];
        void *ptr;

        inet_ntop(res->ai_family, res->ai_addr->sa_data, addrstr, 100);

        switch(res->ai_family)
        {
            case AF_INET:
                ptr = &((struct sockaddr_in *) res->ai_addr)->sin_addr;
                break;
            case AF_INET6:
                ptr = &((struct sockaddr_in6 *) res->ai_addr)->sin6_addr;
                break;
        }

        inet_ntop(res->ai_family, ptr, addrstr, 100);
        printf("IPv%d address: %s (%s)\n", res->ai_family == PF_INET6 ? 6 : 4,
                addrstr, res->ai_canonname);
        res = res->ai_next;
    }
    */

    return ret_val;
}


void signal_handler(__attribute__ ((unused)) int signnum)
{
    printf("caught\n");
    exit_signal = 1;
}

static int do_create_settings(const struct dc_posix_env *env, struct dc_error *err, void *arg)
{
    struct application_settings *app_settings;
    const char                  *ip_version;
    int                          family;
    int                          ret_val;

    DC_TRACE(env);
    app_settings = arg;
    ip_version   = dc_setting_regex_get(env, app_settings->ip_version);

    if(dc_strcmp(env, ip_version, "IPv4") == 0)
    {
        family = PF_INET;
    }
    else if(dc_strcmp(env, ip_version, "IPv6") == 0)
    {
        family = PF_INET6;
    }
    else
    {
        DC_REPORT_USER(env, err, "Invalid ip_version", -1);
    }

    if(DC_HAS_NO_ERROR(err))
    {
        const char *hostname;

        hostname = dc_setting_string_get(env, app_settings->hostname);
        dc_network_get_addresses(env, err, family, SOCK_STREAM, hostname, &app_settings->result);
    }

    if(DC_HAS_ERROR(err))
    {
        ret_val = -1;
    }
    else
    {
        ret_val = 0;
    }

    return ret_val;
}

static int do_create_socket(const struct dc_posix_env *env, struct dc_error *err, void *arg)
{
    struct application_settings *app_settings;
    int                          ret_val;

    DC_TRACE(env);
    app_settings = arg;
    app_settings->server_socket_fd = dc_network_create_socket(env, err, app_settings->result);

    if(DC_HAS_ERROR(err))
    {
        ret_val = -1;
    }
    else
    {
        ret_val = 0;
    }

    return ret_val;
}

static int do_set_sockopts(const struct dc_posix_env *env, struct dc_error *err, void *arg)
{
    struct application_settings *app_settings;
    bool                         reuse_address;
    int                          ret_val;

    DC_TRACE(env);
    app_settings  = arg;
    reuse_address = dc_setting_bool_get(env, app_settings->reuse_address);
    dc_network_reuse_socket(env, err, app_settings->server_socket_fd, reuse_address);

    if(DC_HAS_ERROR(err))
    {
        ret_val = -1;
    }
    else
    {
        ret_val = 0;
    }

    return ret_val;
}

static int do_bind(const struct dc_posix_env *env, struct dc_error *err, void *arg)
{
    struct application_settings *app_settings;
    uint16_t port;
    int ret_val;

    DC_TRACE(env);
    app_settings = arg;
    port         = dc_setting_uint16_get(env, app_settings->port);

    dc_network_bind(env,
                    err,
                    app_settings->server_socket_fd,
                    app_settings->result->ai_addr,
                    port);

    if(DC_HAS_ERROR(err))
    {
        ret_val = -1;
    }
    else
    {
        ret_val = 0;
    }

    return ret_val;
}

static int do_listen(const struct dc_posix_env *env, struct dc_error *err, void *arg)
{
    struct application_settings *app_settings;
    int                          backlog;
    int                          ret_val;

    DC_TRACE(env);
    app_settings = arg;
    backlog = 5;    // TODO: make this a setting
    dc_network_listen(env, err, app_settings->server_socket_fd, backlog);

    if(DC_HAS_ERROR(err))
    {
        ret_val = -1;
    }
    else
    {
        ret_val = 0;
    }

    return ret_val;

}

static int do_setup(const struct dc_posix_env *env, __attribute__ ((unused)) struct dc_error *err, __attribute__ ((unused)) void *arg)
{
    DC_TRACE(env);

    return 0;
}

static int do_accept(const struct dc_posix_env *env, struct dc_error *err, void *arg)
{
    struct application_settings *app_settings;
    int                          client_socket_fd;
    int                          ret_val;

    DC_TRACE(env);
    app_settings = arg;
    client_socket_fd = dc_network_accept(env, err, app_settings->server_socket_fd);

    if(DC_HAS_ERROR(err))
    {
        if(exit_signal == true && DC_ERROR_IS_ERRNO(err, EINTR))
        {
            ret_val = 1;
        }
        else
        {
            ret_val = -1;
        }
    }
    else
    {
        ret_val = 0;
        struct dc_dump_info        *dump_info;
        struct dc_stream_copy_info *copy_info;

        dump_info = dc_dump_info_create(env, err, STDOUT_FILENO, dc_max_off_t(env));

        if(DC_HAS_NO_ERROR(err))
        {
//            copy_info = dc_stream_copy_info_create(env, err, NULL, read_displayer, &client_fd, write_displayer, &client_fd);
            copy_info = dc_stream_copy_info_create(env, err, NULL, dc_dump_dumper, dump_info, NULL, NULL);

            if(DC_HAS_NO_ERROR(err))
            {
                dc_stream_copy(env, err, client_socket_fd, client_socket_fd, 1024, copy_info);

                if(DC_HAS_NO_ERROR(err))
                {
                    dc_stream_copy_info_destroy(env, &copy_info);
                }
            }

            dc_dump_info_destroy(env, &dump_info);
        }
    }

    return ret_val;
}

static int do_shutdown(const struct dc_posix_env *env, __attribute__ ((unused)) struct dc_error *err, void *arg)
{
    struct application_settings *app_settings;

    DC_TRACE(env);
    app_settings = arg;

    return 0;
}

static int do_destroy_settings(const struct dc_posix_env *env, __attribute__ ((unused)) struct dc_error *err, void *arg)
{
    struct application_settings *app_settings;

    DC_TRACE(env);
    app_settings = arg;
    dc_freeaddrinfo(env, app_settings->result);

    return 0;
}

__attribute__ ((unused)) static void write_displayer(__attribute__ ((unused)) const struct dc_posix_env *env, __attribute__ ((unused)) struct dc_error *err, const uint8_t *data, size_t count, __attribute__ ((unused)) size_t file_position, __attribute__ ((unused)) void *arg)
{
    write(STDOUT_FILENO, "SENT: ", 6);
    write(STDOUT_FILENO, data, count);
    write(STDOUT_FILENO, "\n", 1);
}


__attribute__ ((unused)) static void read_displayer(__attribute__ ((unused)) const struct dc_posix_env *env, __attribute__ ((unused)) struct dc_error *err, const uint8_t *data, size_t count, __attribute__ ((unused)) size_t file_position, __attribute__ ((unused)) void *arg)
{
    write(STDOUT_FILENO, "RECV: ", 6);
    write(STDOUT_FILENO, data, count);
    write(STDOUT_FILENO, "\n", 1);
}


static void error_reporter(__attribute__ ((unused)) const struct dc_posix_env *env, const struct dc_error *err)
{
    if(err->type == DC_ERROR_ERRNO)
    {
        fprintf(stderr, "ERROR: %s : %s : @ %zu : %d\n", err->file_name, err->function_name, err->line_number, err->errno_code);
    }
    else
    {
        fprintf(stderr, "ERROR: %s : %s : @ %zu : %d\n", err->file_name, err->function_name, err->line_number, err->err_code);
    }

    fprintf(stderr, "ERROR: %s\n", err->message);
}


__attribute__ ((unused)) static void trace(__attribute__ ((unused)) const struct dc_posix_env *env, const char *file_name, const char *function_name, size_t line_number)
{
    fprintf(stdout, "TRACE: %s : %s : @ %zu\n", file_name, function_name, line_number);
}
