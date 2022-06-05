#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/runtime:5.0 AS base
WORKDIR /app

FROM mcr.microsoft.com/dotnet/sdk:5.0 AS build
WORKDIR /src
COPY ["CriServer.csproj", "."]
RUN dotnet restore "CriServer.csproj"
COPY . .
WORKDIR "/src/"
RUN dotnet build "CriServer.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "CriServer.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
RUN mkdir -p /var/log/criserver
ENTRYPOINT ["dotnet", "CriServer.dll"]
