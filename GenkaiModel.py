import datetime
import random
import ssl
import time
import traceback
from threading import Thread

import cloudscraper
import requests
import warnings

import tls_client
import ua_generator
import web3
from bs4 import BeautifulSoup
from eth_account.messages import encode_defunct
from web3.auto import w3

from logger import logger, MultiThreadLogger

warnings.filterwarnings("ignore", category=DeprecationWarning)


class TwitterAccount:

    def __init__(self, auth_token, csrf, proxy, name):

        self.name = name

        proxy_log = proxy.split(':')[2]
        proxy_pass = proxy.split(':')[3]
        proxy_ip = proxy.split(':')[0]
        proxy_port = proxy.split(':')[1]

        self.session = self._make_scraper()
        self.session.proxies = {'http': f'http://{proxy_log}:{proxy_pass}@{proxy_ip}:{proxy_port}',
                           'https': f'http://{proxy_log}:{proxy_pass}@{proxy_ip}:{proxy_port}'}


        adapter = requests.adapters.HTTPAdapter(max_retries=5)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

        authorization_token = 'AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA'

        self.csrf = csrf
        self.auth_token = auth_token
        self.cookie = f'auth_token={self.auth_token}; ct0={self.csrf}'

        liketweet_headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {authorization_token}',
            'x-csrf-token': self.csrf,
            'cookie': self.cookie,
            'X-Twitter-Active-User': 'yes',
            'X-Twitter-Auth-Type': 'OAuth2Session',
            'X-Twitter-Client-Language':'en',
            'User-Agent': ua_generator.generate(device="desktop").text
        }

        self.session.headers.update(liketweet_headers)

    def Like(self, id):

        # print('asdsd')

        payload = {
            "variables": {
                "tweet_id": str(id)
            },
            "queryId": "lI07N6Otwv1PhnEgXILM7A"
        }

        count = 0
        while count < 2:
            try:
                response = self.session.post("https://api.twitter.com/graphql/lI07N6Otwv1PhnEgXILM7A/FavoriteTweet",  json=payload)
                return True
            except:
                count+=1

        return False


    def Retweet(self, id):
        payload = {
            "variables": {
                "tweet_id": str(id)
            },
            "queryId": "ojPdsZsimiJrUGLR1sjUtA"
        }

        count = 0
        while count < 2:
            try:
                response = self.session.post("https://api.twitter.com/graphql/ojPdsZsimiJrUGLR1sjUtA/CreateRetweet", json=payload)
                return True
            except:
                count+=1
        return False


    def Follow(self, user_id):

        payload = {'include_profile_interstitial_type': 1,
                    'include_blocking': 1,
                    'include_blocked_by': 1,
                    'include_followed_by': 1,
                    'include_want_retweets': 1,
                    'include_mute_edge': 1,
                    'include_can_dm': 1,
                    'include_can_media_tag': 1,
                    'include_ext_has_nft_avatar': 1,
                    'include_ext_is_blue_verified': 1,
                    'include_ext_verified_type': 1,
                    'include_ext_profile_image_shape': 1,
                    'skip_status': 1,
                    'user_id': user_id}

        self.session.headers.update({'Content-Type': 'application/json'})

        response = self.session.post(f"https://twitter.com/i/api/1.1/friendships/create.json?user_id={user_id}&follow=True")
        # print(response.text)

        if 'suspended' in response.text:
            # print(f'Аккаунт {self.name} забанен')
            return 'ban'
        else:
            return 1

    def Tweet(self, text, mediaIds=None, media_group=None):

        if mediaIds == None:

            payload = {"variables": {
                "tweet_text": text,
                "dark_request": False,
                "media": {
                    "media_entities": [],  # {'media_id': ..., 'tagged_users': []}
                    "possibly_sensitive": False
                },
                "withDownvotePerspective": False,
                "withReactionsMetadata": False,
                "withReactionsPerspective": False,
                "withSuperFollowsTweetFields": True,
                "withSuperFollowsUserFields": True,
                "semantic_annotation_ids": []
            }, "features": {
                "tweetypie_unmention_optimization_enabled": True,
                "vibe_api_enabled": True,
                "responsive_web_edit_tweet_api_enabled": True,
                "graphql_is_translatable_rweb_tweet_is_translatable_enabled": True,
                "view_counts_everywhere_api_enabled": True,
                "longform_notetweets_consumption_enabled": True,
                "tweet_awards_web_tipping_enabled": False,
                "interactive_text_enabled": True,
                "responsive_web_text_conversations_enabled": False,
                "responsive_web_twitter_blue_verified_badge_is_enabled": True,
                "responsive_web_graphql_exclude_directive_enabled": False,
                "verified_phone_label_enabled": False,
                "freedom_of_speech_not_reach_fetch_enabled": False,
                "standardized_nudges_misinfo": True,
                "tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled": False,
                "responsive_web_graphql_timeline_navigation_enabled": True,
                "responsive_web_graphql_skip_user_profile_image_extensions_enabled": False,
                "responsive_web_enhance_cards_enabled": False
            },
                "queryId": "SoVnbfCycZ7fERGCwpZkYA"
            }

            count = 0
            while count < 2:
                try:
                    response = self.session.post("https://api.twitter.com/graphql/Tz_cZL9zkkY2806vRiQP0Q/CreateTweet", json=payload)
                    return response.json()['data']['create_tweet']['tweet_results']['result']['rest_id']
                except:
                    count+=1

            return False



        else:

            payload = {"variables": {
                "tweet_text": text,
                "dark_request": False,
                "media": {
                    "media_entities": [{'media_id': str(self.Upload_image(f'Media/{mediaId}.jpg' if media_group == None else f'Media/{media_group}/{mediaId}.jpg')),
                                        'tagged_users': []} for mediaId in mediaIds],
                    # {'media_id': ..., 'tagged_users': []}
                    "possibly_sensitive": False
                },
                "semantic_annotation_ids": []
            }, "features":
                {"tweetypie_unmention_optimization_enabled": True,
                 "vibe_api_enabled": True,
                 "responsive_web_edit_tweet_api_enabled": True,
                 "graphql_is_translatable_rweb_tweet_is_translatable_enabled": True,
                 "view_counts_everywhere_api_enabled": True,
                 "longform_notetweets_consumption_enabled": True,
                 "tweet_awards_web_tipping_enabled": False,
                 "interactive_text_enabled": True,
                 "responsive_web_text_conversations_enabled": False,
                 "longform_notetweets_rich_text_read_enabled": True,
                 "blue_business_profile_image_shape_enabled": True,
                 "responsive_web_graphql_exclude_directive_enabled": True,
                 "verified_phone_label_enabled": False,
                 "freedom_of_speech_not_reach_fetch_enabled": False,
                 "standardized_nudges_misinfo": True,
                 "tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled": False,
                 "responsive_web_graphql_timeline_navigation_enabled": True,
                 "responsive_web_graphql_skip_user_profile_image_extensions_enabled": False,
                 "responsive_web_enhance_cards_enabled": False},
                "queryId": "7TKRKCPuAGsmYde0CudbVg"
            }

            self.session.headers.update({'content-type': 'application/json'})
            response = self.session.post("https://api.twitter.com/graphql/7TKRKCPuAGsmYde0CudbVg/CreateTweet", json=payload)


    def Comment(self, tweet_id, text):

        payload = {"variables":{
            "tweet_text":text,
            "reply":{
                "in_reply_to_tweet_id":tweet_id,
                "exclude_reply_user_ids":[]
            },"dark_request":False,
            "media":{
                "media_entities":[],
                "possibly_sensitive":False
            },"withDownvotePerspective":False,
            "withReactionsMetadata":False,
            "withReactionsPerspective":False,
            "withSuperFollowsTweetFields":True,
            "withSuperFollowsUserFields":True,
            "semantic_annotation_ids":[]
        },"features":{
            "tweetypie_unmention_optimization_enabled":True,
            "vibe_api_enabled":True,
            "responsive_web_edit_tweet_api_enabled":True,
            "graphql_is_translatable_rweb_tweet_is_translatable_enabled":True,
            "view_counts_everywhere_api_enabled":True,
            "longform_notetweets_consumption_enabled":True,
            "tweet_awards_web_tipping_enabled":False,
            "interactive_text_enabled":True,
            "responsive_web_text_conversations_enabled":False,
            "responsive_web_twitter_blue_verified_badge_is_enabled":True,
            "responsive_web_graphql_exclude_directive_enabled":False,
            "verified_phone_label_enabled":False,
            "freedom_of_speech_not_reach_fetch_enabled":False,
            "standardized_nudges_misinfo":True,
            "tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled":False,
            "responsive_web_graphql_timeline_navigation_enabled":True,
            "responsive_web_graphql_skip_user_profile_image_extensions_enabled":False,
            "responsive_web_enhance_cards_enabled":False
        },"queryId":"SoVnbfCycZ7fERGCwpZkYA"
        }

        count = 0
        while count < 2:
            try:
                response = self.session.post('https://api.twitter.com/graphql/Tz_cZL9zkkY2806vRiQP0Q/CreateTweet', json=payload)
                return response.json()['data']['create_tweet']['tweet_results']['result']['rest_id']
            except:
                count+=1

        return False

    def _make_scraper(self):

        ssl_context = ssl.create_default_context()
        ssl_context.set_ciphers(
            "ECDH-RSA-NULL-SHA:ECDH-RSA-RC4-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-RSA-AES128-SHA:ECDH-RSA-AES256-SHA:"
            "ECDH-ECDSA-NULL-SHA:ECDH-ECDSA-RC4-SHA:ECDH-ECDSA-DES-CBC3-SHA:ECDH-ECDSA-AES128-SHA:"
            "ECDH-ECDSA-AES256-SHA:ECDHE-RSA-NULL-SHA:ECDHE-RSA-RC4-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-RSA-AES128-SHA:"
            "ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-NULL-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-ECDSA-DES-CBC3-SHA:"
            "ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:AECDH-NULL-SHA:AECDH-RC4-SHA:AECDH-DES-CBC3-SHA:"
            "AECDH-AES128-SHA:AECDH-AES256-SHA"
        )
        ssl_context.set_ecdh_curve("prime256v1")
        ssl_context.options |= (ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1_3 | ssl.OP_NO_TLSv1)
        ssl_context.check_hostname = False

        return cloudscraper.create_scraper(
            debug=False,
            ssl_context=ssl_context
        )


class Genkai:

    def __init__(self, address, private, tw_auth_token, tw_ct0, proxy, ref_code = ''):

        self.points = 0
        self.token, self.csrf_token = None, None
        self.sitekey = '6LcnRGwnAAAAAH-fdJFy0hD3e4GeYxWkMcbkCwi2'

        self.address, self.private, self.tw_auth_token, self.tw_ct0,  self.ref = address, private, tw_auth_token, tw_ct0,  ref_code
        self.session = self._make_scraper
        self.session.proxies = {"http": f"http://{proxy.split(':')[2]}:{proxy.split(':')[3]}@{proxy.split(':')[0]}:{proxy.split(':')[1]}",
                                "https": f"http://{proxy.split(':')[2]}:{proxy.split(':')[3]}@{proxy.split(':')[0]}:{proxy.split(':')[1]}"}
        adapter = requests.adapters.HTTPAdapter(max_retries=3)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

        self.ua = ua_generator.generate(platform="windows",browser="chrome").text
        self.session.headers.update({"user-agent": self.ua,
                                     'content-type': 'application/json',
                                     'dnt':'1'})

        self.twitter_cookies = {'auth_token':self.tw_auth_token,
                                'ct0':self.tw_ct0}
        self.twitter_cookies_String = f'auth_token={self.tw_auth_token}; ct0={self.tw_ct0}'

    def Registration(self):

        with self.session.get('https://ronin.moku.gg/welcome') as response:
            pass

        message = encode_defunct(text="Welcome to the Ronin x Genkai Quest Adventure.\nSign to start your journey.")
        signed_message = w3.eth.account.sign_message(message, private_key=self.private)
        self.signature = signed_message["signature"].hex()

        payload = {"signature":self.signature,
                   "address":self.address.lower(),
                   "referral":self.ref}

        with self.session.post('https://ronin.moku.gg/api/user/wallet-sign-up', json=payload) as response:
            # print(response.json())
            pass

        with self.session.get('https://ronin.moku.gg/api/auth/providers') as response:
            # print(response.text)
            pass

        with self.session.get('https://ronin.moku.gg/api/auth/csrf') as response:
            # print(response.text)
            self.csrf_token = response.json()['csrfToken']

        p = {'signature': self.signature,
             'wallet': self.address.lower(),
             'callbackUrl': 'https://ronin.moku.gg/',
             'csrfToken': self.csrf_token,
             'json': 'true'}

        self.session.headers.update({'content-type': 'application/x-www-form-urlencoded'})
        with self.session.post('https://ronin.moku.gg/api/auth/callback/web3-wallet?', data=p) as response:
            # print(response.text)
            pass

        self.session.headers.update({'content-type': 'application/json'})

    def TwitterQuest12(self, link):

        payload = {"questId":"b3dba33d-50c4-4eea-8498-504ee39ff931",
                   "inputUrl":link}

        try:
            with self.session.post('https://ronin.moku.gg/api/user/quest/submit/submit-url-quest', json=payload) as response:

                if response.json()['message'] == 'ok':

                    payload = {"questId": "b3dba33d-50c4-4eea-8498-504ee39ff931"}

                    try:
                        with self.session.post('https://ronin.moku.gg/api/user/quest/claim', json=payload) as response:
                            self.points+=1000

                        return True

                    except:

                        return False

                else:

                    return False

        except:

            return False


    def TwitterQuest11(self):

        payload = {"questId": "a14fb6cc-d315-4a1d-860b-86a9361da948"}

        try:
            with self.session.post('https://ronin.moku.gg/api/user/quest/claim', json=payload) as response:
                self.points += 1000

            return True

        except:

            return False
    def TwitterQuest10(self):

        payload = {"questId": "1bf98e74-d7af-4652-91de-f5b1c16bc6db"}

        try:
            with self.session.post('https://ronin.moku.gg/api/user/quest/claim', json=payload) as response:
                self.points += 1000

            return True

        except:

            return False

    def TwitterQuest9(self, link):

        payload = {"questId":"4dfb1d09-b5e4-4249-8686-1400fe74fff7",
                   "inputUrl":link}

        try:
            with self.session.post('https://ronin.moku.gg/api/user/quest/submit/submit-url-quest', json=payload) as response:

                if response.json()['message'] == 'ok':

                    payload = {"questId": "4dfb1d09-b5e4-4249-8686-1400fe74fff7"}

                    try:
                        with self.session.post('https://ronin.moku.gg/api/user/quest/claim', json=payload) as response:
                            self.points+=1000

                        return True

                    except:

                        return False

                else:

                    return False

        except:

            return False


    def TwitterQuest8(self):

        payload = {"questId": "204482ac-8bd4-427a-bdeb-47f0e481dd75"}

        try:
            with self.session.post('https://ronin.moku.gg/api/user/quest/claim', json=payload) as response:
                self.points += 1000

            return True

        except:

            return False
    def TwitterQuest7(self):

        payload = {"questId": "7d8da89a-00d6-4fcd-b2ff-a440dc13ae5b"}

        try:
            with self.session.post('https://ronin.moku.gg/api/user/quest/claim', json=payload) as response:
                self.points += 1000

            return True

        except:

            return False

    def TwitterQuest6(self, link):

        payload = {"questId":"0682572f-421d-4a3d-a4bb-d02e8345a1ba",
                   "inputUrl":link}

        try:
            with self.session.post('https://ronin.moku.gg/api/user/quest/submit/submit-url-quest', json=payload) as response:

                if response.json()['message'] == 'ok':

                    payload = {"questId": "0682572f-421d-4a3d-a4bb-d02e8345a1ba"}

                    try:
                        with self.session.post('https://ronin.moku.gg/api/user/quest/claim', json=payload) as response:
                            self.points+=1000

                        return True

                    except:

                        return False

                else:

                    return False

        except:

            return False

    def TwitterQuest5(self):

        payload = {"questId": "a731cef5-6341-443c-94ae-8b93c4e0f13c"}

        try:
            with self.session.post('https://ronin.moku.gg/api/user/quest/claim', json=payload) as response:
                self.points += 1000

            return True

        except:

            return False
    def TwitterQuest4(self):

        payload = {"questId": "0269e4e4-97df-4ac0-9d3d-9206162eebed"}

        try:
            with self.session.post('https://ronin.moku.gg/api/user/quest/claim', json=payload) as response:
                self.points += 1000

            return True

        except:

            return False

    def TwitterQuest3(self):

        payload = {"questId": "3b5b8a9b-abf1-48a1-b197-9f6b1781f3e0"}

        try:
            with self.session.post('https://ronin.moku.gg/api/user/quest/claim', json=payload) as response:
                self.points += 1000

            return True

        except:

            return False
    def TwitterQuest2(self):

        payload = {"questId": "3a63b3f0-267a-44e0-b4a2-f63e7184d32c"}

        try:
            with self.session.post('https://ronin.moku.gg/api/user/quest/claim', json=payload) as response:
                self.points += 1000

            return True

        except:

            return False

    def TwitterQuest1(self, link):

        payload = {"questId":"5c49d4c9-9327-470b-b568-f7f2064c75ac",
                   "inputUrl":link}

        try:
            with self.session.post('https://ronin.moku.gg/api/user/quest/submit/submit-url-quest', json=payload) as response:

                if response.json()['message'] == 'ok':

                    payload = {"questId": "5c49d4c9-9327-470b-b568-f7f2064c75ac"}

                    try:
                        with self.session.post('https://ronin.moku.gg/api/user/quest/claim', json=payload) as response:
                            self.points+=1000

                        return True

                    except:

                        return False

                else:

                    return False

        except:

            return False

    def CheckDiscordStatus(self):

        try:
            with self.session.get('https://ronin.moku.gg/api/user/query') as response:
                if response.json()['socialAuth']['discord'] != None:
                    return True
                else:
                    return False
        except:
            return False

    def RoninQuest(self):

        payload = {"questId": "9dcefd9d-70f0-48fe-8884-c7d092681fb4"}

        try:
            with self.session.post('https://ronin.moku.gg/api/user/quest/claim', json=payload) as response:
                self.points += 500

            return True

        except:

            return False

    def Checker(self, link) -> bool:

        action = link.split('/')[5].split('?')[0]
        link +=f'&timestamp={datetime.datetime.now().timestamp()}'

        count = 0
        while count < 15:
            count+=1

            with self.session.get(link) as response:
                if response.json()[action] != None:
                    return True

            time.sleep(5)

        return False

    def Play(self):
        self.session.headers.update({'content-type': 'application/json'})
        with self.session.post('https://ronin.moku.gg/api/user/reward/shop/gacha-redeem-queue', json={'id': 11}) as response:
            jobId = response.json()['jobId']

            time.sleep(random.randint(15, 25))

            with self.session.get(f'https://ronin.moku.gg/api/user/reward/shop/get-job-status?jobId={jobId}') as response:
                return response.json()['data']['itemRedeemed']['title']


    @property
    def GetTwitterNickname(self):

        with self.session.get('https://ronin.moku.gg/api/user/query') as response:

            return response.json()['socialAuth']['twitter']

    @property
    def TwitterConnectQuest(self) -> bool:
        payload = {"questId": "0a3de29c-75e7-47de-b554-d4662d1d5c6d"}

        try:
            with self.session.post('https://ronin.moku.gg/api/user/quest/claim', json=payload) as response:
                self.points+=1

            return True

        except:

            return False
    @property
    def DailyQuestClaim(self) -> None:

        payload = {"questId":"a9cbff49-b279-4780-bf95-a7b6197a4ed4"}

        with self.session.post('https://ronin.moku.gg/api/user/quest/claim', json=payload) as response:
            self.points+=4000

        return

    @property
    def ConnectRonin(self)->bool:

        payload = {"signature":self.signature,
                   "address":self.address}

        with self.session.post('https://ronin.moku.gg/api/user/ronin-sign-up', json=payload) as response:
            # print(response.text)
            if response.json()['message'] == "Link wallet successfully.":
                return True
            else:
                return False


    def DiscordConnect(self, discord_token) -> bool:

        try:
            # payload = {"redirectUrl":"https://trove.treasure.lol/treasuretag?edit=true"}
            self.session.headers.update({'authorization': discord_token})

            with self.session.get(
                    f'https://discord.com/api/oauth2/authorize?client_id=1129973683688058941&redirect_uri=https://ronin.moku.gg/api/auth/discord/redirect&response_type=code&scope=identify%20guilds&state=state',
                    timeout=15) as response:
                pass

            with self.session.get(
                    f'https://discord.com/oauth2/authorize?client_id=1129973683688058941&redirect_uri=https://ronin.moku.gg/api/auth/discord/redirect&response_type=code&scope=identify%20guilds&state=state',
                    timeout=15) as response:


                # url = response.json()['loginUrl']
                #
                # state = url.split('state=')[-1].split('&')[0]
                # client_id = url.split('client_id=')[-1].split('&')[0]

                discord_headers = {
                    'authority': 'discord.com',
                    'authorization': discord_token,
                    'content-type': 'application/json',
                    'x-super-properties': 'eyJvcyI6Ik1hYyBPUyBYIiwiYnJvd3NlciI6IkNocm9tZSIsImRldmljZSI6IiIsInN5c3RlbV9sb2NhbGUiOiJydS1SVSIsImJyb3dzZXJfdXNlcl9hZ2VudCI6Ik1vemlsbGEvNS4wIChNYWNpbnRvc2g7IEludGVsIE1hYyBPUyBYIDEwXzE1XzcpIEFwcGxlV2ViS2l0LzUzNy4zNiAoS0hUTUwsIGxpa2UgR2Vja28pIENocm9tZS8xMDkuMC4wLjAgU2FmYXJpLzUzNy4zNiIsImJyb3dzZXJfdmVyc2lvbiI6IjEwOS4wLjAuMCIsIm9zX3ZlcnNpb24iOiIxMC4xNS43IiwicmVmZXJyZXIiOiIiLCJyZWZlcnJpbmdfZG9tYWluIjoiIiwicmVmZXJyZXJfY3VycmVudCI6IiIsInJlZmVycmluZ19kb21haW5fY3VycmVudCI6IiIsInJlbGVhc2VfY2hhbm5lbCI6InN0YWJsZSIsImNsaWVudF9idWlsZF9udW1iZXIiOjE3NDA1MSwiY2xpZW50X2V2ZW50X3NvdXJjZSI6bnVsbCwiZGVzaWduX2lkIjowfQ==',
                }

                payload = {"permissions": "0", "authorize": True}

                with self.session.post(
                        f'https://discord.com/api/v9/oauth2/authorize?client_id=1129973683688058941&response_type=code&redirect_uri=https%3A%2F%2Fronin.moku.gg%2Fapi%2Fauth%2Fdiscord%2Fredirect&scope=identify%20guilds&state=state',
                        json=payload, timeout=15, headers=discord_headers) as response:
                    url = response.json()['location']

                    self.code = url.split('code=')[-1].split('&')[0]

                    with self.session.get(url, timeout=15) as response:
                        # print(f'{self.id} - Discord connected')
                        pass

                    return True
        except:
            return False

    @property
    def GetRef(self) -> str:

        with self.session.get('https://ronin.moku.gg/api/user/get-referral') as response:
            # print(response.text)
            pass

        return response.text
    @property
    def TwitterConnect(self) -> bool:

        with self.session.get('https://ronin.moku.gg/api/user/configs/query?type=twitterId') as response:
            ...

        count = 0
        while count < 4:
            count+=1
            twSession = tls_client.Session(

                client_identifier="chrome115",

                random_tls_extension_order=True

            )
            twSession.proxies = self.session.proxies
            twSession.headers.update({'cookie': self.twitter_cookies_String,
                                      'Authorization': 'Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA',
                                      'content-type':'application/x-www-form-urlencoded',
                                      'X-Csrf-Token': self.tw_ct0,
                                      'user-agent': self.ua})

            response = twSession.get(f'https://twitter.com/i/api/2/oauth2/authorize?code_challenge=challenge&code_challenge_method=plain&client_id=Rml0RzdsNjcwZU1ScXQyUzZ2Tlc6MTpjaQ&redirect_uri=https%3A%2F%2Fronin.moku.gg%2Fapi%2Fauth%2Ftwitter%2Fredirect&response_type=code&scope=tweet.read%20users.read&state=state', allow_redirects=True)
            auth_code = response.json()['auth_code']

            payload = {'approval': 'true',
                       'code': auth_code}

            response = twSession.post(f'https://twitter.com/i/api/2/oauth2/authorize', data=payload)
            link = response.json()['redirect_uri']

            with self.session.get(link) as response:
                ...

            return True

        return False
                # print(response.headers)
    @property
    def Points(self):
        with self.session.get('https://ronin.moku.gg/api/user/reward/get-claimed') as response:
            return response.json()[0]['quantity']

    @property
    def CaptchaSolver(self) -> str:
        from capmonster_python import RecaptchaV2Task

        capmonster = RecaptchaV2Task(self.capKey)
        task_id = capmonster.create_task("https://www.nansen.ai", self.sitekey)
        result = capmonster.join_task_result(task_id)
        # print(result.get("gRecaptchaResponse"))
        return result.get("gRecaptchaResponse")

    @property
    def _make_scraper(self):
        ssl_context = ssl.create_default_context()
        ssl_context.set_ciphers(
            "ECDH-RSA-NULL-SHA:ECDH-RSA-RC4-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-RSA-AES128-SHA:ECDH-RSA-AES256-SHA:"
            "ECDH-ECDSA-NULL-SHA:ECDH-ECDSA-RC4-SHA:ECDH-ECDSA-DES-CBC3-SHA:ECDH-ECDSA-AES128-SHA:"
            "ECDH-ECDSA-AES256-SHA:ECDHE-RSA-NULL-SHA:ECDHE-RSA-RC4-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-RSA-AES128-SHA:"
            "ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-NULL-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-ECDSA-DES-CBC3-SHA:"
            "ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:AECDH-NULL-SHA:AECDH-RC4-SHA:AECDH-DES-CBC3-SHA:"
            "AECDH-AES128-SHA:AECDH-AES256-SHA"
        )
        ssl_context.set_ecdh_curve("prime256v1")
        ssl_context.options |= (ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1_3 | ssl.OP_NO_TLSv1)
        ssl_context.check_hostname = False

        return cloudscraper.create_scraper(
            debug=False,
            ssl_context=ssl_context
        )

def split_list(lst, n):
    k, m = divmod(len(lst), n)
    return (lst[i * k + min(i, m):(i + 1) * k + min(i + 1, m)] for i in range(n))


def Thread_(data, numb):
    time.sleep(random.randint(100, 450) / 100)
    logger = MultiThreadLogger(numb)

    startRefCount = None
    endRefCount = None

    inviteLink = None
    count_ = 0
    dop_count = None

    while count_ < len(data):

        try:

            try:
                if startRefCount > endRefCount:
                    inviteLink = None
            except:
                inviteLink = None

            if inviteLink == None:

                if dop_count != None:
                    acc_ = Genkai(
                        address=data[count_][0],
                        private=data[count_][1],
                        tw_auth_token=data[count_][2][0],
                        tw_ct0=data[count_][2][1],
                        proxy=data[count_][3],
                        ref_code=inviteLink if inviteLink != None else ''
                    )
                    acc_.Registration()
                    acc_.points = acc_.Points

                    if acc_.points > 3000:
                        while (acc_.points - 3000) >= 0:
                            acc_.points -= 3000
                            try:
                                result = acc_.Play()

                                logger.success(f'{data[count_][0]} | Ящик открыт, награда - "{result}"')

                            except:
                                logger.error(f'{data[count_][0]} | Не удалось открыть ящик')

                            time.sleep(random.randint(5, 15))


                startRefCount = 0
                endRefCount = random.randint(2, 6)

            acc = Genkai(
                address=data[count_][0],
                private=data[count_][1],
                tw_auth_token=data[count_][2][0],
                tw_ct0=data[count_][2][1],
                proxy=data[count_][3],
                ref_code=inviteLink if inviteLink != None else ''
            )

            twitterAccount = TwitterAccount(auth_token=acc.tw_auth_token,
                                            csrf=acc.tw_ct0,
                                            proxy=data[count_][3],
                                            name='1')

            acc.Registration()
            logger.success(f'{data[count_][0]} | Регистрация/Авторизация пройдена')

            try:
                if acc.ConnectRonin:
                    acc.RoninQuest()
                    logger.success(f'{data[count_][0]} | Квест "Подключить Ronin" выполнен')
            except:
                # traceback.print_exc()
                pass



            acc.DailyQuestClaim
            logger.success(f'{data[count_][0]} | Ежедневное задание склеймлено')

            if startRefCount == 0:
                dop_count = count_
                inviteLink = acc.GetRef[1:-1].split('referral=')[-1]
                startRefCount += 1

            res = acc.TwitterConnect
            if res:
                logger.success(f'{data[count_][0]} | Успешно приконнекчен твиттер')

                if not acc.CheckDiscordStatus():
                    d_ = 0
                    while d_ < 5:
                        d_+=1

                        a = []
                        with open('Files/discord.txt') as file:
                            for i in file:
                                a.append(i.rstrip())

                        ds_token = a[0]

                        with open('Files/discord.txt', 'w') as file:
                            for i in a[1:]:
                                file.write(i + '\n')

                        if acc.DiscordConnect(ds_token):
                            if acc.CheckDiscordStatus():
                                logger.success(f'{data[count_][0]} | Дискорд подключен успешно')
                                break
                            else:
                                logger.error(f'{data[count_][0]} | Не удалось подключить дискорд')
                        else:
                            logger.error(f'{data[count_][0]} | Не удалось подключить дискорд')
                    if d_ >= 5:
                        a=1+'s'


            #     if acc.TwitterConnectQuest:
            #         logger.success(f'{data[count_][0]} | Квест подключения твиттера выполнен')
            #
            #     nickname = acc.GetTwitterNickname
            #
            #     try:
            #
            #         link = twitterAccount.Tweet(
            #             'Ready for Road to Reveal for #Genkai with @Ronin_Network!\n• Best community\n• Best chain\n• Best place to build\n#Ronin ')
            #
            #         if link != False:
            #             link = f'https://twitter.com/{nickname}/status/{link}'
            #
            #             time.sleep(random.randint(4, 14))
            #
            #             if acc.TwitterQuest1(link):
            #                 logger.success(f'{data[count_][0]} | Квест "Tweet out to support Ronin!" выполнен')
            #         else:
            #             logger.error(f'{data[count_][0]} | Квест "Tweet out to support Ronin!" не выполнен')
            #
            #         time.sleep(random.randint(4, 14))
            #
            #     except:
            #         logger.error(f'{data[count_][0]} | Квест "Tweet out to support Ronin!" не выполнен')
            #         pass
            #
            #     # Axie Champions
            #     try:
            #
            #         twitterAccount.Like(1677209277713518593)
            #         time.sleep(5)
            #
            #         if acc.Checker(
            #                 f'https://ronin.moku.gg/api/twitter/like?tweetId=1677209277713518593&twitterUsername={nickname}&questId=3a63b3f0-267a-44e0-b4a2-f63e7184d32c'):
            #
            #             if acc.TwitterQuest2():
            #                 logger.success(f'{data[count_][0]} | Квест "Axie Champions I" выполнен')
            #
            #         time.sleep(random.randint(4, 14))
            #
            #     except:
            #         logger.error(f'{data[count_][0]} | Квест "Axie Champions I" не выполнен')
            #         pass
            #
            #     try:
            #
            #         twitterAccount.Retweet(1677209277713518593)
            #         time.sleep(5)
            #
            #         if acc.Checker(
            #                 f'https://ronin.moku.gg/api/twitter/retweet?tweetId=1677209277713518593&twitterUsername={nickname}&questId=3b5b8a9b-abf1-48a1-b197-9f6b1781f3e0'):
            #
            #             if acc.TwitterQuest3():
            #                 logger.success(f'{data[count_][0]} | Квест "Axie Champions II" выполнен')
            #
            #         time.sleep(random.randint(4, 14))
            #
            #     except:
            #         logger.error(f'{data[count_][0]} | Квест "Axie Champions II" не выполнен')
            #         pass
            #
            #     # Across Lunacia Quest
            #     try:
            #
            #         twitterAccount.Like(1687479921646379009)
            #         time.sleep(5)
            #
            #         if acc.Checker(
            #                 f'https://ronin.moku.gg/api/twitter/like?tweetId=1687479921646379009&twitterUsername={nickname}&questId=0269e4e4-97df-4ac0-9d3d-9206162eebed'):
            #
            #             if acc.TwitterQuest4():
            #                 logger.success(f'{data[count_][0]} | Квест "Across Lunacia Quest I" выполнен')
            #
            #         time.sleep(random.randint(4, 14))
            #
            #     except:
            #         logger.error(f'{data[count_][0]} | Квест "Across Lunacia Quest I" не выполнен')
            #         pass
            #
            #     try:
            #
            #         twitterAccount.Retweet(1687479921646379009)
            #         time.sleep(5)
            #
            #         if acc.Checker(
            #                 f'https://ronin.moku.gg/api/twitter/retweet?tweetId=1687479921646379009&twitterUsername={nickname}&questId=a731cef5-6341-443c-94ae-8b93c4e0f13c'):
            #
            #             if acc.TwitterQuest5():
            #                 logger.success(f'{data[count_][0]} | Квест "Across Lunacia Quest II" выполнен')
            #
            #         time.sleep(random.randint(4, 14))
            #
            #     except:
            #         logger.error(f'{data[count_][0]} | Квест "Across Lunacia Quest II" не выполнен')
            #         pass
            #
            #     try:
            #
            #         link = twitterAccount.Comment(1687479921646379009, '#MokuLovesArtic')
            #         link = f'https://twitter.com/{nickname}/status/{link}'
            #
            #         time.sleep(5)
            #
            #         if acc.TwitterQuest6(link):
            #             logger.success(f'{data[count_][0]} | Квест "Across Lunacia Quest III" выполнен')
            #
            #         time.sleep(random.randint(4, 14))
            #
            #     except:
            #         logger.error(f'{data[count_][0]} | Квест "Across Lunacia Quest III" не выполнен')
            #         pass
            #
            #     # Genkai Giveaway 3
            #     try:
            #
            #         twitterAccount.Like(1688074662071390208)
            #         time.sleep(5)
            #
            #         if acc.Checker(
            #                 f'https://ronin.moku.gg/api/twitter/like?tweetId=1688074662071390208&twitterUsername={nickname}&questId=7d8da89a-00d6-4fcd-b2ff-a440dc13ae5b'):
            #
            #             if acc.TwitterQuest7():
            #                 logger.success(f'{data[count_][0]} | Квест "Genkai Giveaway 3.1" выполнен')
            #
            #         time.sleep(random.randint(4, 14))
            #
            #     except:
            #         logger.error(f'{data[count_][0]} | Квест "Genkai Giveaway 3.1" не выполнен')
            #         pass
            #
            #     try:
            #
            #         twitterAccount.Retweet(1688074662071390208)
            #         time.sleep(5)
            #
            #         if acc.Checker(
            #                 f'https://ronin.moku.gg/api/twitter/retweet?tweetId=1688074662071390208&twitterUsername={nickname}&questId=204482ac-8bd4-427a-bdeb-47f0e481dd75'):
            #
            #             if acc.TwitterQuest8():
            #                 logger.success(f'{data[count_][0]} | Квест "Genkai Giveaway 3.2" выполнен')
            #
            #         time.sleep(random.randint(4, 14))
            #
            #     except:
            #         logger.error(f'{data[count_][0]} | Квест "Genkai Giveaway 3.2" не выполнен')
            #         pass
            #
            #     try:
            #
            #         link = twitterAccount.Comment(1688074662071390208, 'Congratulations to Grawrz with #RON')
            #         link = f'https://twitter.com/{nickname}/status/{link}'
            #
            #         time.sleep(5)
            #
            #         if acc.TwitterQuest9(link):
            #             logger.success(f'{data[count_][0]} | Квест "Genkai Giveaway 3.3" выполнен')
            #
            #         time.sleep(random.randint(4, 14))
            #
            #     except:
            #         logger.error(f'{data[count_][0]} | Квест "Genkai Giveaway 3.3" не выполнен')
            #         pass
            #
            #     # Genkai Giveaway 4
            #     try:
            #
            #         twitterAccount.Like(1688192081989128192)
            #         time.sleep(5)
            #
            #         if acc.Checker(
            #                 f'https://ronin.moku.gg/api/twitter/like?tweetId=1688192081989128192&twitterUsername={nickname}&questId=1bf98e74-d7af-4652-91de-f5b1c16bc6db'):
            #
            #             if acc.TwitterQuest10():
            #                 logger.success(f'{data[count_][0]} | Квест "Genkai Giveaway 4.1" выполнен')
            #
            #         time.sleep(random.randint(4, 14))
            #
            #     except:
            #         logger.error(f'{data[count_][0]} | Квест "Genkai Giveaway 4.1" не выполнен')
            #         pass
            #
            #     try:
            #
            #         twitterAccount.Retweet(1688192081989128192)
            #         time.sleep(5)
            #
            #         if acc.Checker(
            #                 f'https://ronin.moku.gg/api/twitter/retweet?tweetId=1688192081989128192&twitterUsername={nickname}&questId=a14fb6cc-d315-4a1d-860b-86a9361da948'):
            #
            #             if acc.TwitterQuest11():
            #                 logger.success(f'{data[count_][0]} | Квест "Genkai Giveaway 4.2" выполнен')
            #
            #         time.sleep(random.randint(4, 14))
            #
            #     except:
            #         logger.error(f'{data[count_][0]} | Квест "Genkai Giveaway 4.2" не выполнен')
            #         pass
            #
            #     try:
            #
            #         link = twitterAccount.Comment(1688192081989128192, 'Congratulations to Grawrz with #RON')
            #         link = f'https://twitter.com/{nickname}/status/{link}'
            #
            #         time.sleep(5)
            #
            #         if acc.TwitterQuest12(link):
            #             logger.success(f'{data[count_][0]} | Квест "Genkai Giveaway 4.3" выполнен')
            #
            #         time.sleep(random.randint(4, 14))
            #
            #     except:
            #         logger.error(f'{data[count_][0]} | Квест "Genkai Giveaway 4.3" не выполнен')
            #         pass
            #
            #
            # else:
            #     logger.error(f'{data[count_][0]} | Подключить твиттер не удалось')
            acc.points = acc.Points
            logger.info(f'{data[count_][0]} | Кол-во поинтов на аккаунте: {acc.points}')

            if acc.points > 3000:
                while (acc.points - 3000) >= 0:
                    acc.points -= 3000
                    try:
                        result = acc.Play()

                        logger.success(f'{data[count_][0]} | Ящик открыт, награда - "{result}"')

                    except:
                        logger.error(f'{data[count_][0]} | Не удалось открыть ящик')

                    time.sleep(random.randint(5, 15))

            # print('')

        except Exception as e:
            # traceback.print_exc()
            logger.error(f'{data[count_][0]} | Произошла ошибка - {str(e)}')

            if startRefCount == 1:
                startRefCount = 0

        logger.warning('\n')

        count_ += 1



if __name__ == '__main__':

    print(' ___________________________________________________________________\n'
          '|                       Rescue Alpha Soft                           |\n'
          '|                   Telegram - @rescue_alpha                        |\n'
          '|                   Discord - discord.gg/438gwCx5hw                 |\n'
          '|___________________________________________________________________|\n\n\n')

    threadsCount = 10
    addresses = []
    privates = []
    tw_data = []
    proxy = []

    with open('Files/proxy.txt', 'r', encoding='utf-8') as file:
        for i in file:
            proxy.append(i.rstrip())

    with open('Files/addresses.txt', 'r', encoding='utf-8') as file:
        for i in file:
            addresses.append(i.rstrip())

    with open('Files/privates.txt', 'r', encoding='utf-8') as file:
        for i in file:
            privates.append(i.rstrip())

    with open('Files/tw_data.txt', 'r', encoding='utf-8') as file:
        for i in file:
            tw_data.append([i.rstrip().split('auth_token=')[-1].split(';')[0],i.rstrip().split('ct0=')[-1].split(';')[0]])

    data_ = []
    count = 0
    while count < len(proxy):

        data_.append([addresses[count],
                      privates[count],
                      tw_data[count],
                      proxy[count]])

        count+=1

    allThreads = split_list(data_, threadsCount)

    c = 0
    threads = []
    for i in allThreads:
        thr = Thread(target=Thread_, args=(i, c))
        threads.append(thr)
        c += 1

    for i in threads:
        i.start()

    for i in threads:
        i.join()

    input('\n\nСкрипт успешно завершил работу')

