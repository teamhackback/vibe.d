module app;

import vibe.core.core;
import vibe.core.log;
import vibe.http.auth.basic_auth;
import vibe.http.client;
import vibe.http.router;
import vibe.http.server;
import vibe.web.auth;
import vibe.web.web;

import std.algorithm : among;
import std.datetime;
import std.format : format;


int main()
{
    runTask({
        scope (exit) exitEventLoop();

		auto settings = new HTTPServerSettings;
		settings.port = 9128;
		settings.bindAddresses = ["::1", "127.0.0.1"];
    	auto router = new URLRouter;
    	router.registerWebInterface(new Service);
    	listenHTTP(settings, router);

        logInfo("RUN");
        void test(string url, string user, HTTPStatus expected)
        nothrow {
			logInfo("Test: %s", url);
            try {
                requestHTTP("http://127.0.0.1:9128"~url, (scope req) {
                    if (user !is null) req.addBasicAuth(user, "secret");
                }, (scope res) {
                    res.dropBody();
                    assert(res.statusCode == expected, format("Unexpected status code for GET %s (%s): %s", url, user, res.statusCode));
                });
            } catch (Exception e) {
                assert(false, e.msg);
            }
        }

        test("/1/public", null, HTTPStatus.ok);
        test("/1/any", null, HTTPStatus.unauthorized);
        test("/1/any", "stacy", HTTPStatus.ok);
        test("/1/any_a", null, HTTPStatus.unauthorized);
        test("/1/any_a", "stacy", HTTPStatus.ok);
        test("/1/admin", null, HTTPStatus.unauthorized);
        test("/1/admin", "admin", HTTPStatus.ok);
        test("/1/admin", "peter", HTTPStatus.forbidden);
        test("/1/admin", "stacy", HTTPStatus.forbidden);
        test("/1/admin_a", null, HTTPStatus.unauthorized);
        test("/1/admin_a", "admin", HTTPStatus.ok);
        test("/1/admin_a", "peter", HTTPStatus.forbidden);
        test("/1/admin_a", "stacy", HTTPStatus.forbidden);
        test("/1/member", "admin", HTTPStatus.forbidden);
        test("/1/member", "peter", HTTPStatus.ok);
        test("/1/member", "stacy", HTTPStatus.forbidden);
        test("/1/admin_member", "peter", HTTPStatus.ok);
        test("/1/admin_member", "admin", HTTPStatus.ok);
        test("/1/admin_member", "stacy", HTTPStatus.forbidden);
        test("/2/public", null, HTTPStatus.ok);
        test("/2/any", "stacy", HTTPStatus.ok);
        test("/2/admin", "admin", HTTPStatus.ok);
        test("/3/public", null, HTTPStatus.ok);
        test("/3/any", "stacy", HTTPStatus.ok);
        test("/3/admin", "admin", HTTPStatus.ok);
        logInfo("All auth tests successful.");
    });
    return runEventLoop();
}

struct Auth {
    string username;

    bool isAdmin() { return username == "admin"; }
    bool isMember() { return username == "peter"; }
}

@requiresAuth
@path("/s1")
class Service {
    @noAuth void getPublic(HTTPServerResponse res) { res.writeBody("success"); }
    @anyAuth void getAny(HTTPServerResponse res) { res.writeBody("success"); }
    @anyAuth void getAnyA(HTTPServerResponse res, Auth auth) { assert(auth.username.among("admin", "peter", "stacy")); res.writeBody("success"); }
    @auth(Role.admin) void getAdmin(HTTPServerResponse res) { res.writeBody("success"); }
    @auth(Role.admin) void getAdminA(HTTPServerResponse res, Auth auth) { assert(auth.username == "admin"); res.writeBody("success"); }
    @auth(Role.member) void getMember(HTTPServerResponse res) { res.writeBody("success"); }
    @auth(Role.admin | Role.member) void getAdminMember(HTTPServerResponse res) { res.writeBody("success"); }

    @noRoute Auth authenticate(HTTPServerRequest req, HTTPServerResponse res)
    {
    	import std.stdio;
    	writeln("AAAA");
        Auth ret;
        ret.username = performBasicAuth(req, res, "test", (user, pw) { return pw == "secret"; });
        return ret;
    }
}

@requiresAuth
class ServiceWithAuth {
    @noRoute Auth authenticate(HTTPServerRequest req, HTTPServerResponse res)
    {
        Auth ret;
        ret.username = performBasicAuth(req, res, "test", (user, pw) { return pw == "secret"; });
        return ret;
    }
}

@path("/s2")
class InheritedService : ServiceWithAuth{
    @noAuth void getPublic(HTTPServerResponse res) { res.writeBody("success"); }
    @anyAuth void getAny(HTTPServerResponse res) { res.writeBody("success"); }
    @auth(Role.admin) void getAdmin(HTTPServerResponse res) { res.writeBody("success"); }
}


Auth myAuth(HTTPServerRequest req, HTTPServerResponse res)
{
    Auth ret;
    ret.username = performBasicAuth(req, res, "test", (user, pw) { return pw == "secret"; });
    import std.stdio;
    writeln("FOO");
    return ret;
}

@requiresAuth!myAuth
@path("/s3")
class ServiceWithUDA {
    @noAuth void getPublic(HTTPServerResponse res) { res.writeBody("success"); }
    @anyAuth void getAny(HTTPServerResponse res) { res.writeBody("success"); }
    @auth(Role.admin) void getAdmin(HTTPServerResponse res) { res.writeBody("success"); }
}
