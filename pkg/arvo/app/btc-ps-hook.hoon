/-  *btc-ps-hook, asn1
/+  bip32, bip39, *server, der, default-agent, dbug
|%
+$  card  card:agent:gall
::
+$  versioned-state
  $%  state-zero
  ==
::
+$  state-zero  [%0 base-state]
+$  base-state
  $:  entropy=byts
      url=@t
      store-id=@t
      token=@t
  ==
::
--
=|  state-zero
=*  state  -
%-  agent:dbug
^-  agent:gall
=<
  |_  bol=bowl:gall
  +*  this       .
      api-core  +>
      ac         ~(. api-core bol)
      def        ~(. (default-agent this %|) bol)
  ::
  ++  on-init
    ^-  (quip card _this)
    [~ this]
  ++  on-save   !>(state)
  ++  on-load
    |=  old-vase=vase
    ^-  (quip card _this)
    [~ this(state !<(state-zero old-vase))]
  ::
  ++  on-poke
    |=  [=mark =vase]
    ^-  (quip card _this)
    =^  cards  state
      ?+  mark  (on-poke:def mark vase)
          %btc-ps-admin-action  (poke-btc-ps-admin-action:ac !<(btc-ps-admin-action vase))
          %btc-ps-action        (poke-btc-ps-action:ac !<(btc-ps-action vase))
      ==
    [cards this]
  ::
  ++  on-watch
    |=  =path
    ^-  (quip card _this)
    ?+  path  (on-watch:def path)
        [%http-response *]
      [~ this]
        [%events @ ~]
      [~ this]
    ==
  ::
  ++  on-agent
    |=  [=wire =sign:agent:gall]
    ^-  (quip card _this)
    (on-agent:def wire sign)
  ::
  ++  on-leave  on-leave:def
  ++  on-peek   on-peek:def
  ++  on-arvo
    |=  [=wire =sign-arvo]
    ^-  (quip card _this)
    ?+  +<.sign-arvo  (on-arvo:def wire sign-arvo)
        %http-response
      =^  cards  state
        (http-response:ac wire client-response.sign-arvo)
      [cards this]
    ==
  ::
  ++  on-fail   on-fail:def
  --
::
|_  bol=bowl:gall
++  poke-btc-ps-admin-action
  |=  act=btc-ps-admin-action
  ^-  (quip card _state)
  ?>  (team:title our.bol src.bol)
  ?-  -.act
      %set-store-id
    [~ state(store-id store-id.act)]
  ::
      %set-url
    [~ state(url url.act)]
  ::
      %pair-client
    [[(pair-client pairing-code.act)]~ state]
  ::
      %get-mnemonic
    :_  state
    [%give %fact [/primary]~ %btc-ps-update !>([%mnemonic mnemonic])]~
  ::
      %generate-private-key
    [~ state(entropy `byts`[64 eny.bol])]
  ==
::
++  poke-btc-ps-action
  |=  act=btc-ps-action
  ^-  (quip card _state)
  ?-  -.act
      %get-rates
    [[(get-rates currency-pair.act store-id token)]~ state]
      %create-invoice
    [[(create-invoice currency.act price.act store-id token)]~ state]
  ==
::
++  http-response
  |=  [=wire response=client-response:iris]
  ^-  (quip card _state)
  ::  ignore all but %finished
  ?.  ?=(%finished -.response)
    [~ state]
  ?<  (gth 200 status-code.response-header.response)
  =/  data=mime-data:iris  (need full-file.response)
  ~&  data+data
  =/  =json  (need (de-json:html q.data.data))
  ~&  json+json
  ?+  wire  [~ state]
      [%token @ ~]
    =/  res=btc-ps-hook-response  (parse-response json)
    ?-  -.res
        %error
      ~&  res
      [~ state]
    ::
        %data
      [~ state(token (crip token.res))]
    ==
  ==
::
++  parse-response
  =,  dejs:format
  %-  of:dejs:format
  :~  [
        %data
        %-  ar:dejs:format
        %-  ot:dejs:format
        [%token so]~
      ]
      [%error so]
  ==
::
::  +utilities
::
++  bip32-core
  ~+  ^+  bip32
  (from-seed:bip32 entropy)
::
++  mnemonic  (crip (from-entropy:bip39 entropy))
::
++  pair-client
  |=  pairing-code=@t
  =/  rp=@
    %-  hash160:bip32-core
    public-key:bip32-core
  =/  sin=@t
    %-  crip
    (en-base58check:bip32-core [2 0xf02] [20 rp])
  =/  =request:http
    %+  post-request  'tokens'
    %-  json-to-octs
    %-  pairs:enjs:format
    :~  [%id s+sin]
        [%pairingcode s+pairing-code]
    ==
  (http-request /token/(scot %da now.bol) request *outbound-config:iris)
::
++  create-invoice
  |=  [currency=@t price=@ store-id=@t token=@t]
  =/  =request:http
    %+  signed-post-request  'invoices'
    %-  json-to-octs
    %-  pairs:enjs:format
    :~  [%currency s+currency]
        [%price (numb:enjs:format price)]
        [%token s+token]
    ==
  (http-request /invoice/(scot %da now.bol) request *outbound-config:iris)
::
++  get-rates
  |=  [currency-pair=@t store-id=@t token=@t]
  ^-  card
  =/  =request:http
    %+  signed-get-request  'rates'
    :~  ['currencyPairs' currency-pair]
        ['storeID' store-id]
        ['token' token]
    ==
  (http-request /events/(scot %da now.bol) request *outbound-config:iris)
::
++  http-request
  |=  [=wire =request:http =outbound-config:iris]
  ^-  card
  [%pass wire %arvo %i %request request outbound-config]
::
++  create-signed-headers
  |=  msg=@t
  ^-  (list [@t @t])
  =,  crypto
  =/  msg-sha=@uvI  (sha-256:sha (swp 3 msg))
  =/  signed-msg
    (ecdsa-raw-sign:secp256k1:secp msg-sha private-key:bip32-core)
  =/  enc=[len=@ud dat=@ux]
    %-  en:der
    ^-  spec:asn1
    :-  %seq
    :~  `spec:asn1`[%int `@u`r.signed-msg]
        `spec:asn1`[%int `@u`s.signed-msg]
    ==

  =/  pub=@t
    %-  crip
    :-  '0'
    %+  slag  2
    (scow %x public-key:bip32-core)

  =/  dat=@t
    %-  crip
    %-  flop
    %+  rip  4
    %-  crip
    %+  slag  2
    (scow %x dat.enc)

  :~
    ['X-Identity' pub]
    ['X-Signature' dat]
  ==
::
++  signed-get-request
  |=  [endpoint=@t params=(list [@t @t])]
  ^-  request:http
  =/  hed=header-list:http
    :~  ['Content-Type' 'application/json']
        ['Accept' 'application/json']
        ['User-Agent' 'node-btcpay']
        ['X-Accept-Version' '2.0.0']
        ['connection' 'close']
    ==
  =/  base-url  "https://btcpay464279.lndyn.com/"
  =/  qs  (stringify params)
  =/  url
    (crip (weld (weld base-url (trip endpoint)) (trip qs)))
  ~&  url+url
  =/  signed-hed  (weld hed (create-signed-headers url))
  [%'GET' url signed-hed *(unit octs)]
::
++  signed-post-request
  |=  [endpoint=@t body-octs=octs]
  ^-  request:http
  =/  hed=header-list:http
    :~  ['content-type' 'application/json']
        ['accept' 'application/json']
        ['X-Accept-Version' '2.0.0']
        ['User-Agent' 'urbit-btcpay']
    ==
  =/  base-url  "https://btcpay464279.lndyn.com/"
  =/  url  (crip (weld base-url (trip endpoint)))
  =/  payload
    (crip (weld (trip url) (trip q.body-octs)))
  =/  signed-hed  (weld hed (create-signed-headers payload))
  [%'POST' url signed-hed [~ body-octs]]
::

++  post-request
  |=  [endpoint=@t body-octs=octs]
  ^-  request:http
  =/  hed=header-list:http
    :~  ['content-type' 'application/json']
        ['accept' 'application/json']
        ['X-Accept-Version' '2.0.0']
        ['User-Agent' 'urbit-btcpay']
    ==
  =/  base-url  "https://btcpay464279.lndyn.com/" :: base url need to be in state
  =/  url  (crip (weld base-url (trip endpoint)))
  [%'POST' url hed [~ body-octs]]
::
++  stringify
  |=  params=(list [@t @t])
  ^-  @t
  =/  query-string=tape  ""
  |-
  ^-  @t
  ?~  params  (crip query-string)
  =.  query-string
    %-  zing
    :~  query-string
        ?:(=(query-string "") "?" "&")
        (trip -.i.params)
        "="
        (trip +.i.params)
    ==
  $(params t.params)
--
