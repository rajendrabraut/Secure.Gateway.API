# syntax=docker/dockerfile:1

# ---- build ----
FROM mcr.microsoft.com/dotnet/sdk:11.0 AS build
WORKDIR /src
COPY src/Secure.Gateway.API/Secure.Gateway.API.csproj src/Secure.Gateway.API/
RUN dotnet restore src/Secure.Gateway.API/Secure.Gateway.API.csproj
COPY src/ src/
RUN dotnet publish src/Secure.Gateway.API/Secure.Gateway.API.csproj -c Release -o /app --no-restore /p:UseAppHost=false

# ---- runtime: Ubuntu "chiseled" image = no shell, no package manager, non-root by default ----
FROM mcr.microsoft.com/dotnet/aspnet:10.0-noble-chiseled AS final
WORKDIR /app
COPY --from=build /app .

# Console (stdout) JSON logs are the primary sink in containers; the rolling file goes to /tmp.
ENV ASPNETCORE_URLS=http://+:8080 \
    ASPNETCORE_ENVIRONMENT=Production \
    Serilog__WriteTo__1__Args__path=/tmp/logs/gateway-.json \
    DOTNET_gcServer=1 \
    DOTNET_TieredPGO=1

EXPOSE 8080
USER $APP_UID
ENTRYPOINT ["dotnet", "Secure.Gateway.API.dll"]
