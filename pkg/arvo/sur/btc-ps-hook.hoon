|%
+$  btc-ps-action
  $%  ::  %get-rates: get da rates
      ::
      [%get-rates currency-pair=@t]
      [%create-invoice currency=@t price=@]
  ==
+$  btc-ps-admin-action
  $%
      [%set-store-id store-id=@t]
      [%pair-client pairing-code=@t]
      [%generate-private-key ~]
      [%get-mnemonic ~]
  ==
+$  btc-ps-update
  $%
      [%mnemonic mnemonic=@t]
  ==
+$  btc-ps-hook-response
  $%  [%error @t]
      [%data token=tape]
  ==
--
