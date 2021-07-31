// MIT License
//
// Copyright (c) 2021 Ferhat Geçdoğan All Rights Reserved.
// Distributed under the terms of the MIT License.
//
// curl4cpp - work-in-progress single header libcURL wrapper
// 
// there's so much structs are not wrapped yet
// those are starts with '__'
//
// github.com/ferhatgec/curl4cpp

#ifndef CURL4CPP_CURL4_HPP
#define CURL4CPP_CURL4_HPP

#include <type_traits>
#include <curl/curl.h>

#define CURL4CPP_ENABLE_CTIME

#ifdef CURL4CPP_ENABLE_CTIME
    #include <ctime>
#endif // CURL4CPP_ENABLE_CTIME

using __curl_easyoption       = struct curl_easyoption;
using __curl_easytype         = curl_easytype;
using __curl_httppost         = struct curl_httppost;
using __curl_formget_callback = curl_formget_callback;
using __curl_mime             = curl_mime;
using __curl_mimepart         = curl_mimepart;
using __curl_off_t            = curl_off_t;

using __curl_read_callback    = curl_read_callback;
using __curl_seek_callback    = curl_seek_callback;
using __curl_free_callback    = curl_free_callback;

using __curl_s_list           = struct curl_slist;

using __curl_socket           = curl_socket_t;

using __fd_set                = fd_set;
using __curl_waitfd           = struct curl_waitfd;

namespace curl4 {
    class CURL4 {
    public:
        CURL* init;
    public:
        CURL4() = default;
        ~CURL4()= default;
    };

    namespace easy {
        enum class Type {
            CURL4OT_LONG,
            CURL4OT_VALUES,
            CURL4OT_OFF,
            CURL4OT_OBJECT,
            CURL4OT_STRING,
            CURL4OT_SLIST,
            CURL4OT_CBPTR,
            CURL4OT_BLOB,
            CURL4OT_FUNCTION
        };

        class Option {
        public:
            std::string name;
            CURLoption id;
            Type type;
            unsigned flags;
        public:
            Option() = default;
            ~Option()= default;
        };

        namespace match {
            __curl_easytype from(curl4::easy::Type val) noexcept {
                switch(val) {
                    case curl4::easy::Type::CURL4OT_LONG: {
                        return CURLOT_LONG;
                    }

                    case curl4::easy::Type::CURL4OT_VALUES: {
                        return CURLOT_VALUES;
                    }

                    case curl4::easy::Type::CURL4OT_OFF: {
                        return CURLOT_OFF_T;
                    }

                    case curl4::easy::Type::CURL4OT_OBJECT: {
                        return CURLOT_OBJECT;
                    }

                    case curl4::easy::Type::CURL4OT_STRING: {
                        return CURLOT_STRING;
                    }

                    case curl4::easy::Type::CURL4OT_SLIST: {
                        return CURLOT_SLIST;
                    }

                    case curl4::easy::Type::CURL4OT_CBPTR: {
                        return CURLOT_CBPTR;
                    }

                    case curl4::easy::Type::CURL4OT_BLOB: {
                        return CURLOT_BLOB;
                    }

                    case curl4::easy::Type::CURL4OT_FUNCTION: {
                        return CURLOT_FUNCTION;
                    }
                } return CURLOT_OFF_T;
            }

            Type to(__curl_easytype val) noexcept {
                switch(val) {
                    case CURLOT_LONG: {
                        return curl4::easy::Type::CURL4OT_LONG;
                    }

                    case CURLOT_VALUES: {
                        return curl4::easy::Type::CURL4OT_VALUES;
                    }

                    case CURLOT_OFF_T: {
                        return curl4::easy::Type::CURL4OT_OFF;
                    }

                    case CURLOT_OBJECT: {
                        return curl4::easy::Type::CURL4OT_OBJECT;
                    }

                    case CURLOT_STRING: {
                        return curl4::easy::Type::CURL4OT_STRING;
                    }

                    case CURLOT_SLIST: {
                        return curl4::easy::Type::CURL4OT_SLIST;
                    }

                    case CURLOT_CBPTR: {
                        return curl4::easy::Type::CURL4OT_CBPTR;
                    }

                    case CURLOT_BLOB: {
                        return curl4::easy::Type::CURL4OT_BLOB;
                    }

                    case CURLOT_FUNCTION: {
                        return curl4::easy::Type::CURL4OT_FUNCTION;
                    }
                } return curl4::easy::Type::CURL4OT_OFF;
            }
        }

        void cleanup(CURL4& handle) noexcept {
            curl_easy_cleanup(handle.init);
        }

        CURL4 duphandle(CURL4& handle) noexcept {
            return CURL4 { .init = curl_easy_duphandle(handle.init) };
        }

        std::string escape(CURL4& handle, const std::string str, unsigned length) noexcept {
            return std::string(curl_easy_escape(handle.init, str.c_str(), length));
        }

        template<typename... Param>
        CURLcode getinfo(CURL4& handle, CURLINFO info, Param... args) noexcept {
            return curl_easy_getinfo(handle.init, info, (args, ...));
        }

        CURL4 init() noexcept {
            return CURL4 { .init = curl_easy_init() };
        }

        Option option_by_id(CURLoption id) noexcept {
            auto val = const_cast<__curl_easyoption*>(curl_easy_option_by_id(id));

            return Option { 
                .name = std::string(val->name),
                .id   = val->id,
                .type = match::to(val->type),
                .flags= val->flags
            };
        }

        Option option_by_name(const std::string name) noexcept {
            auto val = const_cast<__curl_easyoption*>(curl_easy_option_by_name(name.c_str()));

            return Option {
                .name = std::string(val->name),
                .id   = val->id,
                .type = match::to(val->type),
                .flags= val->flags
            };
        }

        Option option_next(const Option previous) noexcept {
            __curl_easyoption* value;

            *value = __curl_easyoption {
                .name = previous.name.c_str(),
                .id   = previous.id,
                .type = match::from(previous.type),
                .flags= previous.flags
            };

            auto val = const_cast<__curl_easyoption*>(curl_easy_option_next(value));

            return Option {
                .name = std::string(val->name),
                .id   = val->id,
                .type = match::to(val->type),
                .flags= val->flags
            };
        }

        CURLcode pause(CURL4& handle, int bitmask) noexcept {
            return curl_easy_pause(handle.init, bitmask);
        }

        CURLcode perform(CURL4& easy_handle) noexcept {
            return curl_easy_perform(easy_handle.init);
        }

        template<typename Buffer>
        CURLcode recv(CURL4& handle, 
                      Buffer* buffer, 
                      std::size_t buffer_length, 
                      std::size_t* n) noexcept {
            return curl_easy_recv(handle.init, buffer, buffer_length, n);
        }
        
        void reset(CURL4& handle) noexcept {
            curl_easy_reset(handle.init);
        }

        template<typename Buffer>
        CURLcode send(CURL4& handle, 
                      const Buffer* buffer, 
                      std::size_t buffer_length,
                      std::size_t* n) noexcept {
            return curl_easy_send(handle.init, buffer, buffer_length, n);
        }

        template<typename Param>
        CURLcode setopt(CURL4& handle, CURLoption option, Param parameter) noexcept {
            return curl_easy_setopt(handle.init, option, parameter);
        }

        const std::string strerror(CURLcode error) noexcept {
            return std::string(curl_easy_strerror(error));
        }

        std::string unescape(CURL4& handle, 
                             std::string url, 
                            unsigned inlength, 
                            int* outlength) noexcept {
            return curl_easy_unescape(handle.init, url.c_str(), inlength, outlength);
        } 

        CURLcode upkeep(CURL4& handle) noexcept {
            return curl_easy_upkeep(handle.init);
        }
    }

    namespace form {
        // deprecated
        // deprecated

        class HTTPPost {
        public:
            __curl_httppost* init;
        public:
            HTTPPost() = default;
            ~HTTPPost()= default;
        };

        template<typename Param>
        int get(HTTPPost& form, Param userp, __curl_formget_callback append) noexcept {
            return curl_formget(form.init, userp, append);
        }
    }

    // Not thread safe (for C++20 there will be new date utils)
    #ifdef CURL4CPP_ENABLE_CTIME
        namespace date {
            std::time_t get(std::string date, std::time_t* now) noexcept {
                return curl_getdate(date.data(), now);
            }
        }
    #endif // CURL4CPP_ENABLE_CTIME

    namespace global {
        enum SSLBackendTypes {
            CURL4SSLBACKEND_NONE = 0,
            CURL4SSLBACKEND_OPENSSL = 1,
            CURL4SSLBACKEND_GNUTLS = 2,
            CURL4SSLBACKEND_NSS = 3,
            CURL4SSLBACKEND_GSKIT = 5,
            CURL4SSLBACKEND_POLARSSL = 6,
            CURL4SSLBACKEND_WOLFSSL = 7,
            CURL4SSLBACKEND_SCHANNEL = 8,
            CURL4SSLBACKEND_SECURETRANSPORT = 9,
            CURL4SSLBACKEND_AXTLS = 10,
            CURL4SSLBACKEND_MBEDTLS = 11,
            CURL4SSLBACKEND_MESALINK = 12,
            CURL4SSLBACKEND_BEARSSL = 13
        };


        class SSLBackend {
        public:
            SSLBackendTypes id;
            std::string name;
        public:
            SSLBackend() = default;
            ~SSLBackend() = default;

            SSLBackendTypes get_id() {
                return this->id;
            }

            std::string get_name() {
                return this->name;
            }
        };

        namespace ssl {
            curl_sslbackend from(SSLBackendTypes type) noexcept {
                switch(type) {
                    case CURL4SSLBACKEND_NONE: {
                        return CURLSSLBACKEND_NONE;
                    }

                    case CURL4SSLBACKEND_OPENSSL: {
                        return CURLSSLBACKEND_OPENSSL;
                    }

                    case CURL4SSLBACKEND_GNUTLS: {
                        return CURLSSLBACKEND_GNUTLS;
                    }

                    case CURL4SSLBACKEND_NSS: {
                        return CURLSSLBACKEND_NSS;
                    }

                    case CURL4SSLBACKEND_GSKIT: {
                        return CURLSSLBACKEND_GSKIT;
                    }

                    case CURL4SSLBACKEND_POLARSSL: {
                        return CURLSSLBACKEND_POLARSSL;
                    }

                    case CURL4SSLBACKEND_WOLFSSL: {
                        return CURLSSLBACKEND_WOLFSSL;
                    }

                    case CURL4SSLBACKEND_SCHANNEL: {
                        return CURLSSLBACKEND_SCHANNEL;
                    }

                    case CURL4SSLBACKEND_SECURETRANSPORT: {
                        return CURLSSLBACKEND_SECURETRANSPORT;
                    }

                    case CURL4SSLBACKEND_AXTLS: {
                        return CURLSSLBACKEND_AXTLS;
                    }

                    case CURL4SSLBACKEND_MBEDTLS: {
                        return CURLSSLBACKEND_MBEDTLS;
                    }

                    case CURL4SSLBACKEND_MESALINK: {
                        return CURLSSLBACKEND_MESALINK;
                    }

                    case CURL4SSLBACKEND_BEARSSL: {
                        return CURLSSLBACKEND_BEARSSL;
                    }
                } return CURLSSLBACKEND_NONE;
            }


            CURLsslset set(SSLBackendTypes __id, std::string name, SSLBackend*** __avail) noexcept {
                auto __val = ***__avail;
                
                curl_ssl_backend*** val;

                ***val = curl_ssl_backend {
                    .id = ssl::from(__val.id),
                    .name = __val.name.c_str()
                };

                return curl_global_sslset(ssl::from(__id), 
                                          name.c_str(), const_cast<const curl_ssl_backend***>(val));
            }
        }

        void cleanup() noexcept {
            curl_global_cleanup();
        }

        CURLcode init(long flags) noexcept {
            return curl_global_init(flags);
        }

        using __curl_malloc_callback = curl_malloc_callback;
        using __curl_free_callback   = curl_free_callback;
        using __curl_realloc_callback= curl_realloc_callback;
        using __curl_strdup_callback = curl_strdup_callback;
        using __curl_calloc_callback = curl_calloc_callback;

        CURLcode init_mem(long flags,
                          curl_malloc_callback m,
                          curl_free_callback f,
                          curl_realloc_callback r,
                          curl_strdup_callback s,
                          curl_calloc_callback c) noexcept {
            return curl_global_init_mem(flags, m, f, r, s, c);
        }
    }

    namespace mime {
        __curl_mimepart* addpart(__curl_mime* mime) noexcept {
            return curl_mime_addpart(mime);
        }

        CURLcode data(__curl_mimepart* part, const std::string data, std::size_t data_size) noexcept {
            return curl_mime_data(part, data.c_str(), data_size);           
        }

        template<typename Param>
        CURLcode data_cb(__curl_mimepart* part, 
                         __curl_off_t* data_size,
                         __curl_read_callback readfunc, 
                         __curl_seek_callback seekfunc,
                         __curl_free_callback freefunc, Param arg) noexcept {
            return curl_mime_data_cb(part, data_size, readfunc, seekfunc, freefunc, arg);
        }

        CURLcode encoder(__curl_mimepart* part, std::string encoding) noexcept {
            return curl_mime_encoder(part, encoding.c_str());
        }

        CURLcode filedata(__curl_mimepart* part, const std::string filename) noexcept {
            return curl_mime_filedata(part, filename.c_str());
        }

        CURLcode filename(__curl_mimepart* part, const std::string filename) noexcept {
            return curl_mime_filename(part, filename.c_str());
        }

        void free(__curl_mime*& mime) noexcept {
            curl_mime_free(mime);
        }

        CURLcode headers(__curl_mimepart* part, __curl_s_list* headers, int take_ownership) noexcept {
            return curl_mime_headers(part, headers, take_ownership);
        }

        __curl_mime* init(CURL4& handle) noexcept {
            return curl_mime_init(handle.init);
        }

        CURLcode name(__curl_mimepart* part, const std::string name) noexcept {
            return curl_mime_name(part, name.c_str());
        }

        CURLcode subparts(__curl_mimepart* part, __curl_mime* subparts) noexcept {
            return curl_mime_subparts(part, subparts);
        }

        CURLcode type(__curl_mimepart* part, const std::string mimetype) noexcept {
            return curl_mime_type(part, mimetype.c_str());
        }
    }

    namespace multi {
        using __CURLMcode = CURLMcode;
        using __CURLMSG   = CURLMSG;
        using __CURLMoption = CURLMoption;

        class CURL4M {
        public:
            CURLM* init;
        public:
            CURL4M() = default;
            ~CURL4M()= default;
        };

        template<typename Value>
        class CURL4Msg {
        public:
            __CURLMSG msg;
            CURL4* handle;
            
            union {
                Value* whatever;
                CURLcode result;
            } data;
        public:
            CURL4Msg() = default;
            ~CURL4Msg()= default;
        };

        __CURLMcode add_handle(CURL4M& multi_handle, CURL4& handle) noexcept {
            return curl_multi_add_handle(multi_handle.init, handle.init);
        }

        template<typename Param>
        __CURLMcode assign(CURL4M& multi_handle, __curl_socket sockfd, Param arg) noexcept {
            return curl_multi_assign(multi_handle.init, sockfd, arg);
        }

        __CURLMcode cleanup(CURL4M& multi_handle) noexcept {
            return curl_multi_cleanup(multi_handle.init);
        }

        __CURLMcode fdset(CURL4M& multi_handle,
                          __fd_set* read_fd_set,
                          __fd_set* write_fd_set,
                          __fd_set* exc_fd_set,
                          int* max_fd) noexcept {
            return curl_multi_fdset(multi_handle.init, read_fd_set, write_fd_set, exc_fd_set, max_fd);
        }

        template<typename Value>
        CURL4Msg<Value> info_read(CURL4M& multi_handle, int* msgs_in_queue) noexcept {
            auto val = curl_multi_info_read(multi_handle.init, msgs_in_queue);

            return CURL4Msg<Value> {
                .msg = val->msg,
                .handle = CURL4 { .init = val->easy_handle },
                .data = val->data
            };
        }

        CURL4M init() noexcept {
            return CURL4M {
                .init = curl_multi_init()
            };
        }

        __CURLMcode perform(CURL4M& multi_handle, int* running_handles) noexcept {
            return curl_multi_perform(multi_handle.init, running_handles);
        }
        
        __CURLMcode remove_handle(CURL4M& mutli_handle, CURL4& handle) noexcept {
            return curl_multi_remove_handle(mutli_handle.init, handle.init);
        }

        template<typename Param>
        __CURLMcode setopt(CURL4M& multi_handle, __CURLMoption option, Param parameter) noexcept {
            return curl_multi_setopt(multi_handle.init, option, parameter);
        }

        __CURLMcode socket_action(CURL4M& multi_handle, 
                                  __curl_socket sockfd, 
                                  int ev_bitmask, 
                                  int* running_handles) noexcept {
            return curl_multi_socket_action(multi_handle.init, sockfd, ev_bitmask, running_handles);
        }

        const std::string strerror(__CURLMcode error_num) noexcept {
            return std::string(curl_multi_strerror(error_num));
        }

        __CURLMcode timeout(CURL4M& multi_handle, long* timeout) noexcept {
            return curl_multi_timeout(multi_handle.init, timeout);
        }

        __CURLMcode poll(CURL4M& multi_handle,
                         __curl_waitfd extra_fds[],
                         unsigned extra_nfds,
                         int timeout_ms,
                         int* numfds) noexcept {
            return curl_multi_poll(multi_handle.init, extra_fds, extra_nfds, timeout_ms, numfds);
        }

        __CURLMcode wait(CURL4M& multi_handle, 
                         __curl_waitfd extra_fds[],
                         unsigned extra_nfds,
                         int timeout_ms,
                         int* numfds) noexcept {
            return curl_multi_wait(multi_handle.init, extra_fds, extra_nfds, timeout_ms, numfds);
        }

        __CURLMcode wakeup(CURL4M& multi_handle) noexcept {
            return curl_multi_wakeup(multi_handle.init);
        }
    }

    namespace share {
        using __CURLSH       = CURLSH;
        using __CURLSHcode   = CURLSHcode;
        using __CURLSHoption = CURLSHoption;

        __CURLSHcode cleanup(__CURLSH* share_handle) noexcept {
            return curl_share_cleanup(share_handle);
        }

        __CURLSH* init() noexcept {
            return curl_share_init();
        }

        template<typename Param>
        __CURLSHcode setopt(__CURLSH* share, CURLSHoption option, Param parameter) noexcept {
            return curl_share_setopt(share, option, parameter);
        }

        const std::string strerror(__CURLSHcode errornum) noexcept {
            return std::string(curl_share_strerror(errornum));
        }
    }

    namespace slist {
        __curl_s_list* append(__curl_s_list* list, const std::string str) noexcept {
            return curl_slist_append(list, str.c_str());
        }

        void free_all(__curl_s_list* list) noexcept {
            curl_slist_free_all(list);
        }
    }

    namespace url {
        using __CURLU     = CURLU;
        using __CURLUcode = CURLUcode;
        using __CURLUPart = CURLUPart;

        __CURLU* init() noexcept {
            return curl_url();
        }

        void cleanup(__CURLU* handle) noexcept {
            curl_url_cleanup(handle);
        }

        __CURLU* dup(__CURLU* inhandle) noexcept {
            return curl_url_dup(inhandle);
        }

        __CURLUcode get(__CURLU* url,
                        __CURLUPart what,
                        char** part, // std::string
                        unsigned flags) noexcept {
            return curl_url_get(url, what, part, flags);
        }

        __CURLUcode set(__CURLU* url, 
                        __CURLUPart part,
                        const std::string content,
                        unsigned flags) noexcept {
            return curl_url_set(url, part, content.c_str(), flags);
        }
    }

    namespace version {
        using __curl_version_info_data = curl_version_info_data;
        using __CURLversion            = CURLversion;

        std::string version() noexcept {
            return std::string(curl_version());
        }

        __curl_version_info_data* version_info(__CURLversion age) noexcept {
            return curl_version_info(age);
        }
    }

    void free(char*& ptr) noexcept {
        curl_free(ptr);
    }
}

#endif // CURL4CPP_CURL4_HPP