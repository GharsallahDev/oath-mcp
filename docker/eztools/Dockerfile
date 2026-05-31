# OATH — Eric Zimmerman's tools (EZ tools) in a pinned .NET 9 container.
#
# Pins:
#   - .NET 9.0.0 (SDK runtime — EZ tools target net9.0)
#   - dotnet-tools.json controls which tools + which versions get installed.
#
# Tools available after build (invoke as `dotnet TOOLNAME` inside the container):
#   - MFTECmd       — $MFT, $J ($UsnJrnl), $LogFile, $Boot, $SDS, $I30 parser
#   - EvtxECmd      — Windows Event Log (.evtx) parser with Sigma-style maps
#   - AmcacheParser — Amcache.hve parser
#   - PECmd         — Prefetch parser
#   - SrumECmd      — SRUDB.dat (process / network / energy) parser
#   - WxTCmd        — Windows Timeline ActivitiesCache.db parser
#   - RECmd         — Registry hive parser with batch-mode plugins
#   - SBECmd        — ShellBags parser
#   - JLECmd        — Jump List parser
#   - LECmd         — LNK (shortcut) parser
#
# All tools accept `--csv-output` or `--json-output` for structured output that
# the OATH typed-functions layer can deterministically re-derive against.

FROM mcr.microsoft.com/dotnet/sdk:9.0

# Working dir for tool execution. Mounts inbound: /evidence (RO), /output (RW).
WORKDIR /work
VOLUME ["/evidence", "/output"]

# Install EZ tools via dotnet-tools.json manifest (pinned versions).
COPY dotnet-tools.json /work/.config/dotnet-tools.json
RUN cd /work && dotnet tool restore && dotnet tool list

# Add the local tool manifest dir to PATH so `EvtxECmd` etc. are callable.
ENV PATH="/root/.dotnet/tools:${PATH}"
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1
ENV DOTNET_NOLOGO=1

# Quick self-check — fails the build if any tool was misnamed or unreleased.
RUN dotnet EvtxECmd --version || (echo "EvtxECmd not found" && exit 1)
RUN dotnet MFTECmd --version || (echo "MFTECmd not found" && exit 1)

# Idle entrypoint; the OATH MCP server `docker exec`s into this container.
CMD ["tail", "-f", "/dev/null"]
