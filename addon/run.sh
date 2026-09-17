#!/usr/bin/env bashio
# Home Assistant add-on entrypoint: map add-on options to the bridge's env vars.
set -e

export BASEUS_ACCOUNT="$(bashio::config 'account')"
export BASEUS_PASSWORD="$(bashio::config 'password')"
export BASEUS_REGION="$(bashio::config 'region')"
export BASEUS_COUNTRYCODE="$(bashio::config 'country_code')"
export BASEUS_FRAMERATE="$(bashio::config 'framerate')"

if bashio::config.true 'include_offline'; then
    export BASEUS_INCLUDE_OFFLINE=1
else
    export BASEUS_INCLUDE_OFFLINE=0
fi

if bashio::config.is_empty 'account' || bashio::config.is_empty 'password'; then
    bashio::exit.nok "Set your Baseus 'account' and 'password' in the add-on Configuration tab."
fi

bashio::log.info "Starting Baseus Cam Bridge (RTSP :8554, HLS :8888, WebRTC :8889)..."
exec python3 -m baseus_bridge serve
