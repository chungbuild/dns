export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === '/api/detect-dns') {
      return handleDetectDNS(request);
    }

    return new Response('DNS Security Hub API', {
      headers: { 'Content-Type': 'text/plain' }
    });
  }
};

async function handleDetectDNS(request) {
  const headers = {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET',
  };

  try {
    const clientIP = request.headers.get('cf-connecting-ip') || 'unknown';
    const colo = request.headers.get('cf-ray') ? request.headers.get('cf-ray').split('-')[1] : 'unknown';

    const providers = [
      { name: 'Cloudflare', url: 'https://1.1.1.1/dns-query', dot: '1.1.1.1' },
      { name: 'Google', url: 'https://dns.google/dns-query', dot: 'dns.google' },
      { name: 'Quad9', url: 'https://dns.quad9.net/dns-query', dot: 'dns.quad9.net' },
      { name: 'AdGuard', url: 'https://dns.adguard.com/dns-query', dot: 'dns.adguard.com' },
      { name: 'NextDNS', url: 'https://firefox.dns.nextdns.io/dns-query', dot: 'firefox.dns.nextdns.io' },
    ];

    const testDomain = 'cloudflare.com';
    const detectionResults = [];

    const queries = providers.map(async (provider) => {
      const startTime = Date.now();
      try {
        const dohURL = new URL(provider.url);
        dohURL.searchParams.set('name', testDomain);
        dohURL.searchParams.set('type', 'A');

        const response = await fetch(dohURL.toString(), {
          headers: { 'Accept': 'application/dns-json' },
          signal: AbortSignal.timeout(3000),
        });

        const elapsed = Date.now() - startTime;

        if (response.ok) {
          const data = await response.json();
          const ips = data.Answer
            ? data.Answer.filter(a => a.type === 1).map(a => a.data)
            : [];

          return {
            name: provider.name,
            dot: provider.dot,
            status: 'ok',
            ip: ips[0] || null,
            latency: elapsed,
          };
        }

        return { name: provider.name, dot: provider.dot, status: 'error', latency: elapsed };
      } catch (e) {
        return { name: provider.name, dot: provider.dot, status: 'timeout', latency: Date.now() - startTime };
      }
    });

    const results = await Promise.all(queries);

    return new Response(JSON.stringify({
      clientIP,
      results,
    }), { headers });

  } catch (e) {
    return new Response(JSON.stringify({ error: e.message }), {
      status: 500,
      headers,
    });
  }
}
