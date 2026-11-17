"""Keep authenticated HTTP requests on their explicitly configured origin."""
import urllib.error
import urllib.parse
import urllib.request


class SameOriginRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        def origin(url):
            parsed = urllib.parse.urlsplit(url)
            return parsed.scheme.lower(), parsed.hostname, parsed.port or (443 if parsed.scheme == 'https' else 80)
        if origin(req.full_url) != origin(newurl):
            raise urllib.error.HTTPError(req.full_url, 403, 'Cross-origin redirect refused', headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def open_request(request, *, timeout):
    return urllib.request.build_opener(SameOriginRedirect()).open(request, timeout=timeout)
