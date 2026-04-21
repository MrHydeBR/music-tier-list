# Music Tier List 🎵

Site interativo para classificar músicas de uma playlist do Spotify em tiers S a F com drag-and-drop, estilos editáveis, exportação para PNG e compartilhamento via link.

![Music Tier List](https://img.shields.io/badge/spotify-integrated-1db954?logo=spotify&logoColor=white) ![GitHub Pages](https://img.shields.io/badge/deploy-github%20pages-222)

## Funcionalidades

- **Integração real com Spotify** via OAuth PKCE (sem backend, sem segredos)
- **Tier list drag-and-drop** com 6 níveis (S, A, B, C, D, F)
- **Estilos musicais editáveis** (renomear, cor, adicionar, remover) — vem com Rock, Grunge, Pop, Festa, Relax e Classic por padrão
- **Filtro por estilo** para classificar por gênero
- **Exportar como PNG** para postar em redes sociais
- **Compartilhar via link** — o estado completo é codificado na URL
- **Tema claro/escuro** com alternância rápida
- **Responsivo** — funciona em desktop e mobile

## Como configurar (só na primeira vez)

### 1. Criar um app no Spotify Developer

1. Acesse [developer.spotify.com/dashboard](https://developer.spotify.com/dashboard) e faça login
2. Clique em **Create app** (pode usar qualquer nome, ex: "Music Tier List")
3. Na configuração do app, em **Redirect URIs**, adicione a URL onde o site vai rodar:
   - Exemplo GitHub Pages: `https://seu-usuario.github.io/tierlist/`
   - Exemplo local: `http://localhost:5000/`
   - **Importante:** a barra final `/` precisa bater com o que o site mostra no campo "Redirect URI"
4. Em **APIs used**, marque apenas **Web API**
5. Salve e copie o **Client ID** do app

### 2. Usar o site

1. Abra o site publicado
2. No card "Configurar Spotify", cole o Client ID e clique em Salvar
3. Clique em **Entrar com Spotify** e autorize
4. Cole o link de qualquer playlist do Spotify (ex: `https://open.spotify.com/playlist/37i9dQZEVXbMXbN3EUUhlg`) e clique em **Carregar**
5. Arraste as capas entre os tiers

## Publicar no GitHub Pages

Depois de fazer fork / clonar este repositório:

1. Vá em **Settings → Pages** do seu repositório no GitHub
2. Em **Source**, escolha **Deploy from a branch**
3. Selecione a branch `main` (ou `master`) e a pasta `/ (root)`
4. Salve — o site estará disponível em `https://seu-usuario.github.io/nome-do-repo/` em 1-2 minutos

Depois de publicar, lembre-se de adicionar o Redirect URI correto no seu app do Spotify Developer (exatamente como aparece no card do site).

## Rodar localmente

Qualquer servidor HTTP estático serve. Opções:

```bash
# Python
python3 -m http.server 5000

# Node (npx)
npx serve -p 5000

# PHP
php -S localhost:5000
```

Depois abra [http://localhost:5000](http://localhost:5000).

Para Spotify funcionar localmente, adicione `http://localhost:5000/` como Redirect URI no seu app do Spotify Developer.

## Stack

- **HTML + CSS + JS vanilla** — sem build, sem framework
- [SortableJS](https://github.com/SortableJS/Sortable) para drag-and-drop
- [html2canvas](https://html2canvas.hertzen.com/) para exportar PNG
- [Spotify Web API](https://developer.spotify.com/documentation/web-api) com OAuth PKCE

## Notas técnicas

- **Sem storage** — o site funciona 100% em memória. Para persistir sua classificação, use o botão **Compartilhar** que codifica tudo na URL.
- **OAuth PKCE sem backend** — o verifier é passado pelo parâmetro `state` do OAuth (já que `sessionStorage` pode ser bloqueado em alguns sandboxes). PKCE garante a segurança do fluxo sem precisar de client secret.

## Licença

MIT
