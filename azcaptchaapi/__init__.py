from __future__ import unicode_literals, print_function, absolute_import, division


import sys
import aiohttp
import asyncio
import aiofiles
from io import BytesIO


# ----------------------------------------------------------------------------------------------- #
# [Python version compatibility]                                                                  #
# ----------------------------------------------------------------------------------------------- #


if sys.version_info[0] == 2:
    from HTMLParser import HTMLParser
elif sys.version_info[0] == 3:
    from html.parser import HTMLParser


if sys.version_info[:2] >= (3, 5):
    # Py3.5 and upwards provide a function directly in the root module.
    from html import unescape
else:
    # For older versions, we use the bound method.
    unescape = HTMLParser().unescape


# ----------------------------------------------------------------------------------------------- #
# [Exception types]                                                                               #
# ----------------------------------------------------------------------------------------------- #


class AZCaptchaApiError(Exception):
    """Base class for all AZCaptcha API exceptions."""
    pass


class CommunicationError(AZCaptchaApiError):
    """An error occurred while communicating with the AZCaptcha API."""
    pass


class ResponseFormatError(AZCaptchaApiError):
    """The response data doesn't fit what we expected."""
    pass


class OperationFailedError(AZCaptchaApiError):
    """The AZCaptcha API indicated failure of an operation."""
    pass


# ----------------------------------------------------------------------------------------------- #
# [Internal convenience decorators]                                                               #
# ----------------------------------------------------------------------------------------------- #


def _rewrite_http_to_com_err(func):
    """Rewrites HTTP exceptions from `requests` to `CommunicationError`s."""
    async def proxy(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except aiohttp.client_exceptions.ClientError:
            raise CommunicationError(
                "an error occurred while communicating with the AZCaptcha API"
            )
    return proxy


def _rewrite_to_format_err(*exception_types):
    """Rewrites arbitrary exception types to `ResponseFormatError`s."""
    def decorator(func):
        async def proxy(*args, **kwargs):
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                if any(isinstance(e, x) for x in exception_types):
                    raise ResponseFormatError("unexpected response format")
                raise
        return proxy
    return decorator


def retry_on_timeout(max_retries, wait_time=1):
    def decorator(func):
        async def wrapper(*args, **kwargs):
            retries = 0
            while retries < max_retries:
                try:
                    result = await func(*args, **kwargs)
                    return result
                except Exception as e:
                    retries += 1
                    if retries == max_retries:
                        raise
                    await asyncio.sleep(wait_time)
        return wrapper
    return decorator
# ----------------------------------------------------------------------------------------------- #
# [Public API]                                                                                    #
# ----------------------------------------------------------------------------------------------- #


class AZCaptchaApi(object):
    """Provides an interface to the AZCaptcha API."""
    BASE_URL = 'http://azcaptcha.com'
    REQ_URL = BASE_URL + '/in.php'
    RES_URL = BASE_URL + '/res.php'
    LOAD_URL = BASE_URL + '/load.php'

    def __init__(self, api_key):
        self.api_key = api_key

    async def get(self, url, params, **kwargs):
        """Sends a HTTP GET, for low-level API interaction."""
        params['key'] = self.api_key
        async with aiohttp.ClientSession() as session:
            return await session.get(url, params=params, **kwargs)

    async def post(self, url, data, **kwargs):
        """Sends a HTTP POST, for low-level API interaction."""
        data.add_field('key', self.api_key)
        async with aiohttp.ClientSession() as session:
            return await session.post(url, data=data, **kwargs)

    @_rewrite_http_to_com_err
    @_rewrite_to_format_err(ValueError)
    async def get_balance(self):
        """Obtains the balance on our account, in dollars."""
        resp = await self.get(self.RES_URL, {
            'action': 'getbalance'
        })
        return float(await resp.text())

    @_rewrite_http_to_com_err
    async def get_stats(self, date):
        """Obtains statistics about our account, as XML."""
        resp = await self.get(self.RES_URL, {
            'action': 'getstats',
            'date': date if type(date) == str else date.isoformat(),
        })
        return await resp.text()

    @_rewrite_http_to_com_err
    async def get_load(self):
        """Obtains load statistics of the server."""
        resp = await self.get(self.LOAD_URL, {})
        return await resp.text()

    @_rewrite_http_to_com_err
    @_rewrite_to_format_err(IndexError, ValueError)
    async def solve(self, file, captcha_parameters=None):
        """
        Queues a captcha for solving. `file` may either be a path or a file object.
        Optional parameters for captcha solving may be specified in a `dict` via
        `captcha_parameters`, for valid values see section "Additional CAPTCHA parameters"
        in API documentation here:

        https://azcaptcha.com/
        """

        # If path was provided, load file.
        if type(file) == str:
            async with aiofiles.open(file, mode='rb') as f:
                raw_data = await f.read()
        else:
            raw_data = await file.read()

        # Send request.
        form_data = aiohttp.FormData()
        data = captcha_parameters or {'method': 'post'}
        for k, v in data.items():
            form_data.add_field(k, v)
        form_data.add_field('file', BytesIO(raw_data))

        resp = await self.post(
            self.REQ_URL,
            data=form_data
        )
        text = await resp.text()

        # Success?
        if '|' in text:
            _, captcha_id = text.split('|')
            return Captcha(self, captcha_id)

        # Nope, failure.
        raise OperationFailedError("Operation failed: %r" % (text,))


class Captcha(object):
    """Represents a captcha that was queued for solving."""

    def __init__(self, api, captcha_id):
        """
        Constructs a new captcha awaiting result. Instances should not be created
        manually, but using the `TwoCaptchaApi.solve` method.

        :type api: TwoCaptchaApi
        """
        self.api = api
        self.captcha_id = captcha_id
        self._cached_result = None
        self._reported_bad = False

    @_rewrite_http_to_com_err
    @_rewrite_to_format_err(ValueError)
    @retry_on_timeout(max_retries=3, wait_time=1)
    async def try_get_result(self):
        """
        Tries to obtain the captcha text. If the result is not yet available,
        `None` is returned.
        """
        if self._cached_result is not None:
            return self._cached_result

        resp = await self.api.get(self.api.RES_URL, {
            'action': 'get',
            'id': self.captcha_id,
        })
        text = await resp.text()

        # Success?
        if '|' in text:
            _, captcha_text = unescape(text).split('|')
            self._cached_result = captcha_text
            return captcha_text

        # Nope, either failure or not ready, yet. Yep, they mistyped "Captcha".
        if text in ('CAPCHA_NOT_READY', 'CAPTCHA_NOT_READY'):
            return None

        # Failure.
        raise OperationFailedError("Operation failed: %r" % (text,))

    async def await_result(self, sleep_time=1.):
        """
        Obtains the captcha text in a blocking manner.
        Retries every `sleep_time` seconds.
        """
        while True:
            # print('Trying to obtain result ..')
            result = await self.try_get_result()
            if result is not None:
                break
            await asyncio.sleep(sleep_time)
        return result

    @_rewrite_http_to_com_err
    async def report_bad(self):
        """Reports to the server that the captcha was solved incorrectly."""
        if self._cached_result is None:
            raise ValueError("tried reporting bad state for captcha not yet retrieved")
        if self._reported_bad:
            raise ValueError("tried double-reporting bad captcha")

        resp = await self.api.get(self.api.RES_URL, {
            'action': 'reportbad',
            'id': self.captcha_id,
        })
        if resp.text != 'OK_REPORT_RECORDED':
            raise ResponseFormatError("unexpected API response")
