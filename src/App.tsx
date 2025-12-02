import React, { useState, useEffect, useRef } from 'react';
import { 
  Globe, Search, Database, Trash2, ChevronRight, Loader2, 
  AlertCircle, Copy, ArrowLeft, Shield, RefreshCw, Clock, 
  AlertTriangle, Lock, Eye, Activity, Wifi, Filter, Camera, 
  LayoutGrid, List, ImageOff, Cpu, Server, StopCircle, X, 
  Network, Download, Share2, Plus, Zap, Layers, ShoppingCart, 
  BarChart3, Code, ExternalLink, FileSpreadsheet, ShieldCheck,
  CheckCircle2, XCircle
} from 'lucide-react';

// --- Types ---

interface TechStack {
  name: string;
  category: 'cms' | 'server' | 'framework' | 'cdn' | 'lang' | 'analytics' | 'ui' | 'ecommerce';
}

interface SecurityHeaders {
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  missing: string[];
  present: string[];
}

interface SubdomainRecord {
  name: string;
  source: 'crt.sh' | 'alienvault' | 'mixed';
  issuer: string;
  notBefore: string;
  notAfter: string;
  isWildcard: boolean;
  firstSeenAt: string;
  lastSeenAt: string;
  resolutionStatus?: 'unknown' | 'active' | 'dead';
  ipAddress?: string;
  security?: SecurityHeaders;
  technologies?: TechStack[];
}

interface DomainRecord {
  id: string;
  domain: string;
  nameServers: string[]; 
  subdomains: SubdomainRecord[];
  createdAt: number;
  lastScannedAt: number;
  status: 'scanned' | 'error';
  stats: {
    total: number;
    expired: number;
    wildcard: number;
    expiringSoon: number;
    active?: number;
    techIdentified?: number;
    lowSecurity?: number;
  };
}

// --- ANALYSIS ENGINES ---

const SIGNATURES = {
  cms: [
    { name: 'WordPress', pattern: /wp-content|wp-includes|generator="WordPress"/i },
    { name: 'Drupal', pattern: /Drupal|sites\/all\/themes/i },
    { name: 'Joomla', pattern: /Joomla!/i },
    { name: 'Wix', pattern: /wix\.com|wix-site/i },
    { name: 'Squarespace', pattern: /static\.squarespace\.com/i },
    { name: 'Ghost', pattern: /ghost-sdk|generator="Ghost"/i },
  ],
  ecommerce: [
    { name: 'Shopify', pattern: /cdn\.shopify\.com|Shopify\.design/i },
    { name: 'WooCommerce', pattern: /woocommerce/i },
    { name: 'Magento', pattern: /mage\/cookies/i },
    { name: 'Stripe', pattern: /stripe\.com\/v3/i },
  ],
  framework: [
    { name: 'React', pattern: /react-dom|_react|react-root/i },
    { name: 'Vue.js', pattern: /vue\.js|data-v-/i },
    { name: 'Angular', pattern: /ng-version|angular\.js/i },
    { name: 'Next.js', pattern: /__NEXT_DATA__/i },
    { name: 'jQuery', pattern: /jquery\.js/i },
  ],
  server: [
    { name: 'Nginx', pattern: /nginx/i },
    { name: 'Apache', pattern: /Apache/i },
    { name: 'Vercel', pattern: /vercel/i },
    { name: 'Netlify', pattern: /netlify/i },
    { name: 'AWS', pattern: /amazonaws/i },
    { name: 'Cloudflare', pattern: /__cfduid|cf-ray|cloudflare/i },
  ],
  analytics: [
    { name: 'Google Analytics', pattern: /google-analytics\.com|gtag/i },
    { name: 'Hotjar', pattern: /hotjar\.com/i },
    { name: 'Segment', pattern: /segment\.com/i },
  ]
};

const analyzeTarget = async (domain: string): Promise<{ tech: TechStack[], security: SecurityHeaders }> => {
  const result = {
    tech: [] as TechStack[],
    security: { grade: 'F', missing: [], present: [] } as SecurityHeaders
  };

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 8000); 
    const response = await fetch(`https://corsproxy.io/?https://${domain}`, { method: 'GET', signal: controller.signal });
    clearTimeout(timeoutId);

    if (!response.ok) return result;

    const html = await response.text();
    const headers = response.headers;
    const content = (html + JSON.stringify(Array.from(headers.entries()))).toLowerCase();

    Object.entries(SIGNATURES).forEach(([category, sigs]) => {
      sigs.forEach(sig => {
        if (sig.pattern.test(content)) {
          if (!result.tech.find(d => d.name === sig.name)) {
            result.tech.push({ name: sig.name, category: category as any });
          }
        }
      });
    });

    const criticalHeaders = [
      { key: 'strict-transport-security', label: 'HSTS' },
      { key: 'content-security-policy', label: 'CSP' },
      { key: 'x-frame-options', label: 'X-Frame' },
      { key: 'x-content-type-options', label: 'NoSniff' },
      { key: 'referrer-policy', label: 'Referrer' }
    ];

    let score = 0;
    criticalHeaders.forEach(h => {
      if (headers.get(h.key)) {
        score++;
        result.security.present.push(h.label);
      } else {
        result.security.missing.push(h.label);
      }
    });

    if (score === 5) result.security.grade = 'A';
    else if (score === 4) result.security.grade = 'B';
    else if (score >= 2) result.security.grade = 'C';
    else if (score >= 1) result.security.grade = 'D';
    else result.security.grade = 'F';

    return result;
  } catch (e) { return result; }
};

// --- API HELPERS ---

const fetchReverseNS = async (ns: string): Promise<string[]> => {
  const cleanNs = ns.replace(/\.$/, '').trim();
  const targetUrl = `https://api.hackertarget.com/findshareddns/?q=${cleanNs}`;
  try {
    const res = await fetch(`https://corsproxy.io/?${encodeURIComponent(targetUrl)}`);
    const text = await res.text();
    if (text.includes('.') && !text.includes('error') && !text.includes('limit') && !text.includes('API count exceeded')) {
       return text.split('\n').map(d => d.trim()).filter(d => d.length > 0);
    }
  } catch (e) { }
  try {
     const res = await fetch(`https://api.allorigins.win/get?url=${encodeURIComponent(targetUrl)}`);
     const json = await res.json();
     const text = json.contents;
     if (text && text.includes('.') && !text.includes('error')) {
        return text.split('\n').map((d: string) => d.trim()).filter((d: string) => d.length > 0);
     }
  } catch (e) { }
  return [];
};

const fetchNameServers = async (domain: string): Promise<string[]> => {
  try {
    const res = await fetch(`https://dns.google/resolve?name=${domain}&type=NS`);
    const data = await res.json();
    return data.Answer ? data.Answer.map((r: any) => r.data.replace(/\.$/, '')) : [];
  } catch (e) { return []; }
};

const checkDnsResolution = async (hostname: string): Promise<{ active: boolean, ip?: string }> => {
  try {
    const res = await fetch(`https://dns.google/resolve?name=${hostname}&type=A`);
    const data = await res.json();
    if (data.Status === 0 && data.Answer) {
      const record = data.Answer.find((r: any) => r.type === 1);
      return { active: true, ip: record ? record.data : undefined };
    }
  } catch (e) { }
  return { active: false };
};

const fetchSubdomains = async (domain: string): Promise<SubdomainRecord[]> => {
  const clean = domain.trim().toLowerCase();
  const [crtData, otxData] = await Promise.all([
    fetch(`https://corsproxy.io/?https://crt.sh/?q=%.${clean}&output=json`).then(r => r.ok ? r.json() : []).catch(() => []),
    fetch(`https://corsproxy.io/?https://otx.alienvault.com/api/v1/indicators/domain/${clean}/passive_dns`).then(r => r.ok ? r.json() : {}).catch(() => ({}))
  ]);

  const map = new Map<string, SubdomainRecord>();
  const now = new Date().toISOString();

  if (Array.isArray(crtData)) {
    crtData.forEach((entry: any) => {
      const names = entry.name_value.split('\n');
      names.forEach((name: string) => {
        const cleanName = name.replace('*.', '').toLowerCase();
        if (!cleanName.endsWith(clean) || map.has(cleanName)) return;
        map.set(cleanName, {
          name: cleanName,
          source: 'crt.sh',
          issuer: (entry.issuer_name.match(/O=([^,]+)/) || [])[1] || 'Unknown',
          notBefore: entry.not_before,
          notAfter: entry.not_after,
          isWildcard: entry.name_value.includes('*.'),
          firstSeenAt: now,
          lastSeenAt: now,
          resolutionStatus: 'unknown',
          technologies: []
        });
      });
    });
  }

  if (otxData.passive_dns && Array.isArray(otxData.passive_dns)) {
    otxData.passive_dns.forEach((entry: any) => {
        const cleanName = entry.hostname.toLowerCase();
        if (!cleanName.endsWith(clean)) return;
        if (map.has(cleanName)) {
            const existing = map.get(cleanName)!;
            existing.source = 'mixed';
        } else {
            map.set(cleanName, {
                name: cleanName,
                source: 'alienvault',
                issuer: 'OTX',
                notBefore: '',
                notAfter: '',
                isWildcard: false,
                firstSeenAt: entry.first || now,
                lastSeenAt: entry.last || now,
                resolutionStatus: 'unknown',
                technologies: []
            });
        }
    });
  }

  return Array.from(map.values()).sort((a,b) => a.name.localeCompare(b.name));
};

const getScreenshotUrl = (hostname: string) => {
  return `https://api.microlink.io/?url=https://${hostname}&screenshot=true&meta=false&embed=screenshot.url`;
};

const getFaviconUrl = (hostname: string) => {
  return `https://www.google.com/s2/favicons?domain=${hostname}&sz=256`;
};

// --- HELPERS FOR CERT DATES ---

const getDaysRemaining = (dateStr: string) => {
  if (!dateStr) return 0;
  const diff = new Date(dateStr).getTime() - new Date().getTime();
  return Math.ceil(diff / (1000 * 3600 * 24));
};

const isExpired = (dateStr: string) => getDaysRemaining(dateStr) < 0;
const isExpiringSoon = (dateStr: string) => {
  const days = getDaysRemaining(dateStr);
  return days > 0 && days < 30;
};

// --- COMPONENTS ---

const Badge = ({ children, color = 'blue', onClick, className = '' }: any) => {
  const colors = {
    blue: 'bg-blue-500/10 text-blue-400 border-blue-500/20 hover:bg-blue-500/20',
    red: 'bg-red-500/10 text-red-400 border-red-500/20',
    green: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
    purple: 'bg-purple-500/10 text-purple-400 border-purple-500/20',
    orange: 'bg-orange-500/10 text-orange-400 border-orange-500/20',
    slate: 'bg-slate-800 text-slate-400 border-slate-700 hover:bg-slate-700 hover:text-white',
  };
  return (
    <span 
      onClick={onClick}
      className={`text-xs px-2 py-0.5 rounded border ${colors[color as keyof typeof colors]} font-medium whitespace-nowrap flex items-center gap-1 transition-colors ${onClick ? 'cursor-pointer' : ''} ${className}`}
    >
      {children}
    </span>
  );
};

const GradeBadge = ({ grade }: { grade?: string }) => {
  if (!grade) return null;
  const colors = {
    'A': 'bg-green-500 text-white border-green-600',
    'B': 'bg-emerald-500 text-white border-emerald-600',
    'C': 'bg-yellow-500 text-black border-yellow-600',
    'D': 'bg-orange-500 text-white border-orange-600',
    'F': 'bg-red-600 text-white border-red-700'
  };
  return (
    <div className={`w-6 h-6 flex items-center justify-center rounded font-bold text-xs border shadow-sm ${colors[grade as keyof typeof colors] || colors.F}`}>
      {grade}
    </div>
  );
};

const TechBadge = ({ tech }: { tech: TechStack }) => {
  const colors = {
    cms: 'bg-orange-500/10 text-orange-400 border-orange-500/20',
    server: 'bg-slate-500/10 text-slate-400 border-slate-500/20',
    framework: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
    cdn: 'bg-purple-500/10 text-purple-400 border-purple-500/20',
    lang: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
    analytics: 'bg-pink-500/10 text-pink-400 border-pink-500/20',
    ui: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20',
    ecommerce: 'bg-green-600/10 text-green-400 border-green-500/20',
  };
  return (
    <span className={`text-[10px] uppercase px-1.5 py-0.5 rounded border ${colors[tech.category] || colors.server} font-semibold truncate max-w-[80px]`}>
      {tech.name}
    </span>
  );
};

const Button = ({ children, onClick, variant = 'primary', className = '', disabled = false, icon: Icon }: any) => {
  const baseStyle = "flex items-center justify-center px-4 py-2 rounded-lg font-medium transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed text-sm";
  const variants = {
    primary: "bg-blue-600 hover:bg-blue-700 text-white shadow-lg shadow-blue-500/30",
    secondary: "bg-slate-700 hover:bg-slate-600 text-slate-200 border border-slate-600",
    ghost: "text-slate-400 hover:text-slate-200 hover:bg-slate-800"
  };
  return (
    <button onClick={onClick} disabled={disabled} className={`${baseStyle} ${variants[variant as keyof typeof variants]} ${className}`}>
      {Icon && <Icon className="w-4 h-4 mr-2" />}
      {children}
    </button>
  );
};

const DomainThumbnail = ({ subdomain }: { subdomain: SubdomainRecord }) => {
  const [imgSrc, setImgSrc] = useState<string>(getScreenshotUrl(subdomain.name));
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [isFavicon, setIsFavicon] = useState(false);

  const handleError = () => {
    if (!isFavicon) {
      setImgSrc(getFaviconUrl(subdomain.name));
      setIsFavicon(true);
      setLoading(false); 
    } else {
      setLoading(false);
      setError(true);
    }
  };

  return (
    <div className="bg-slate-800 border border-slate-700 rounded-lg overflow-hidden group hover:border-blue-500/50 transition-colors h-full flex flex-col relative">
       {subdomain.security?.grade && <div className="absolute top-2 left-2 z-20"><GradeBadge grade={subdomain.security.grade} /></div>}
       <div className={`aspect-video bg-slate-950 relative overflow-hidden ${isFavicon ? 'flex items-center justify-center p-8' : ''}`}>
         {loading && !error && <div className="absolute inset-0 flex items-center justify-center bg-slate-900 z-10"><Loader2 className="w-6 h-6 text-slate-600 animate-spin" /></div>}
         {error ? (
            <div className="absolute inset-0 flex flex-col items-center justify-center text-slate-600">
               <ImageOff className="w-8 h-8 mb-2 opacity-50" />
               <span className="text-xs">Unavailable</span>
            </div>
         ) : (
            <img 
              src={imgSrc} 
              className={`transition-opacity duration-500 ${loading ? 'opacity-0' : 'opacity-100'} ${isFavicon ? 'w-16 h-16 object-contain' : 'w-full h-full object-cover'}`}
              onLoad={() => setLoading(false)}
              onError={handleError}
              loading="lazy"
              alt={subdomain.name}
            />
         )}
         <div className={`absolute top-2 right-2 w-2.5 h-2.5 rounded-full border border-slate-900 shadow-sm ${subdomain.resolutionStatus === 'active' ? 'bg-emerald-500' : subdomain.resolutionStatus === 'dead' ? 'bg-red-500' : 'bg-slate-500'}`} />
       </div>
       <div className="p-3 flex-1 flex flex-col bg-slate-800 relative">
         <div className="flex justify-between items-start mb-2"><h4 className="font-bold text-sm text-slate-200 truncate pr-2 w-full">{subdomain.name}</h4></div>
         <div className="flex flex-wrap gap-1 mt-auto min-h-[20px]">{subdomain.technologies?.slice(0, 3).map((t, i) => <TechBadge key={i} tech={t} />)}</div>
         <div className="mt-3 flex justify-between items-center text-xs">
            {subdomain.ipAddress ? <span className="text-slate-500 font-mono">{subdomain.ipAddress}</span> : <span className="text-slate-600">-</span>}
            {isFavicon && <span className="text-[9px] text-slate-600 uppercase">Logo Only</span>}
         </div>
       </div>
    </div>
  );
};

// --- MODALS ---

const TechProfileModal = ({ subdomain, onClose }: { subdomain: SubdomainRecord, onClose: () => void }) => {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/80 backdrop-blur-sm animate-in fade-in" onClick={onClose}>
      <div className="bg-slate-800 border border-slate-700 rounded-xl max-w-lg w-full shadow-2xl p-6" onClick={e => e.stopPropagation()}>
        <div className="flex justify-between items-center mb-6">
          <h3 className="text-xl font-bold text-white flex items-center gap-2"><ShieldCheck className="w-6 h-6 text-blue-400"/> Risk Profile</h3>
          <button onClick={onClose}><X className="w-5 h-5 text-slate-400 hover:text-white"/></button>
        </div>
        <div className="space-y-6">
           <div className="flex items-center justify-between p-4 bg-slate-900 rounded-lg border border-slate-700">
              <div>
                 <p className="text-slate-400 text-xs uppercase font-bold tracking-wider mb-1">Target</p>
                 <p className="text-white font-mono text-lg">{subdomain.name}</p>
                 {subdomain.ipAddress && <p className="text-slate-500 text-sm font-mono mt-1">IP: {subdomain.ipAddress}</p>}
                 {subdomain.notAfter && (
                    <p className={`text-xs mt-1 ${isExpired(subdomain.notAfter) ? 'text-red-400' : 'text-green-400'}`}>
                       Cert Expires: {new Date(subdomain.notAfter).toLocaleDateString()}
                    </p>
                 )}
              </div>
              <div className="flex flex-col items-center">
                 <div className={`w-12 h-12 flex items-center justify-center rounded-lg text-2xl font-bold border-2 ${
                    subdomain.security?.grade === 'A' ? 'border-green-500 text-green-500' :
                    subdomain.security?.grade === 'F' ? 'border-red-500 text-red-500' : 'border-yellow-500 text-yellow-500'
                 }`}>
                    {subdomain.security?.grade || '-'}
                 </div>
                 <span className="text-[10px] text-slate-500 mt-1 uppercase font-bold">Grade</span>
              </div>
           </div>
           <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                 <h4 className="text-sm text-slate-400 font-bold uppercase mb-3 flex items-center gap-2"><Lock className="w-4 h-4"/> Security Headers</h4>
                 <div className="space-y-2">
                    {subdomain.security?.present.map((h, i) => (<div key={i} className="flex items-center gap-2 text-xs text-green-400"><ShieldCheck className="w-3 h-3"/> {h}</div>))}
                    {subdomain.security?.missing.map((h, i) => (<div key={i} className="flex items-center gap-2 text-xs text-red-400"><AlertTriangle className="w-3 h-3"/> Missing {h}</div>))}
                    {(!subdomain.security || (subdomain.security.present.length === 0 && subdomain.security.missing.length === 0)) && <span className="text-slate-600 text-xs italic">No headers analyzed yet.</span>}
                 </div>
              </div>
              <div>
                 <h4 className="text-sm text-slate-400 font-bold uppercase mb-3 flex items-center gap-2"><Cpu className="w-4 h-4"/> Technology</h4>
                 <div className="flex flex-wrap gap-2">
                    {subdomain.technologies?.map((t, i) => (<div key={i} className="bg-slate-700/50 px-2 py-1 rounded text-xs text-slate-200 border border-slate-600">{t.name}</div>))}
                    {(!subdomain.technologies || subdomain.technologies.length === 0) && <span className="text-slate-600 text-xs italic">Unknown stack.</span>}
                 </div>
              </div>
           </div>
        </div>
      </div>
    </div>
  );
};

const ReverseNSModal = ({ ns, onClose, onImport }: { ns: string, onClose: () => void, onImport: (domain: string) => void }) => {
  const [domains, setDomains] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;
    fetchReverseNS(ns).then(res => { if (mounted) { setDomains(res); setLoading(false); }});
    return () => { mounted = false; };
  }, [ns]);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/90 backdrop-blur-md animate-in fade-in" onClick={onClose}>
      <div className="bg-slate-800 border border-slate-700 rounded-xl max-w-lg w-full shadow-2xl overflow-hidden flex flex-col max-h-[80vh]" onClick={e => e.stopPropagation()}>
        <div className="p-4 border-b border-slate-700 flex justify-between items-center bg-slate-800">
          <div>
            <h3 className="text-lg font-bold text-white flex items-center gap-2"><Share2 className="w-5 h-5 text-purple-400" /> Shared Infrastructure</h3>
            <p className="text-slate-400 text-xs mt-1">Domains using <span className="text-blue-300 font-mono">{ns}</span></p>
          </div>
          <button onClick={onClose}><X className="w-5 h-5 text-slate-400 hover:text-white"/></button>
        </div>
        <div className="flex-1 overflow-auto bg-slate-900/50 p-0">
          {loading ? (
             <div className="flex flex-col items-center justify-center h-48 space-y-3"><Loader2 className="w-8 h-8 text-purple-500 animate-spin" /><p className="text-slate-500 text-sm">Querying database...</p></div>
          ) : domains.length === 0 ? (
             <div className="flex flex-col items-center justify-center h-48 space-y-3 text-slate-500 p-6 text-center">
               <Share2 className="w-8 h-8 opacity-20" /><p>No results found or API limited.</p>
               <a href={`https://viewdns.info/reversens/?ns=${ns}`} target="_blank" rel="noreferrer" className="mt-2 text-blue-400 hover:text-blue-300 text-sm flex items-center gap-1">Try external search <ExternalLink className="w-3 h-3" /></a>
             </div>
          ) : (
            <table className="w-full text-left text-sm text-slate-300">
              <tbody className="divide-y divide-slate-700/50">
                {domains.map((d, i) => (
                  <tr key={i} className="hover:bg-slate-700/30">
                    <td className="p-3 font-mono">{d}</td>
                    <td className="p-3 text-right"><button onClick={() => onImport(d)} className="text-xs bg-slate-700 hover:bg-blue-600 text-white px-2 py-1 rounded transition-colors flex items-center gap-1 ml-auto"><Plus className="w-3 h-3" /> Track</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
};

const ScreenshotModal = ({ subdomain, onClose }: { subdomain: string, onClose: () => void }) => {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const src = getScreenshotUrl(subdomain);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/90 backdrop-blur-md animate-in fade-in" onClick={onClose}>
      <div className="bg-slate-800 border border-slate-700 rounded-xl max-w-4xl w-full shadow-2xl overflow-hidden flex flex-col max-h-[90vh]" onClick={e => e.stopPropagation()}>
        <div className="p-4 border-b border-slate-700 flex justify-between items-center bg-slate-800">
          <h3 className="text-lg font-semibold text-white flex items-center gap-2"><Camera className="w-5 h-5 text-blue-400" /> Visual: {subdomain}</h3>
          <button onClick={onClose}><X className="w-5 h-5 text-slate-400 hover:text-white"/></button>
        </div>
        <div className="flex-1 overflow-auto bg-slate-950 flex items-center justify-center p-4 min-h-[400px]">
          {loading && !error && <Loader2 className="w-10 h-10 text-blue-500 animate-spin" />}
          {error && <div className="text-center text-slate-500"><ImageOff className="w-12 h-12 mx-auto mb-2 opacity-50" /><p>Unavailable</p></div>}
          <img src={src} className={`max-w-full h-auto rounded shadow-lg ${loading ? 'hidden' : 'block'}`} onLoad={() => setLoading(false)} onError={() => { setLoading(false); setError(true); }} />
        </div>
        <div className="p-4 border-t border-slate-700 bg-slate-800 flex justify-end">
           <a href={src} target="_blank" download className="flex items-center text-sm text-blue-400 hover:text-blue-300"><Download className="w-4 h-4 mr-2" /> Open Full Size</a>
        </div>
      </div>
    </div>
  );
};

export default function App() {
  const [domains, setDomains] = useState<DomainRecord[]>([]);
  const [selectedDomain, setSelectedDomain] = useState<DomainRecord | null>(null);
  const [loading, setLoading] = useState(false);
  const [processing, setProcessing] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [tableSearch, setTableSearch] = useState('');
  const [viewMode, setViewMode] = useState<'list'|'gallery'>('list');
  const [progress, setProgress] = useState(0);
  const [filterType, setFilterType] = useState<'all' | 'live' | 'expired' | 'expiring' | 'wildcard'>('all');
  
  // Modals
  const [screenshotSub, setScreenshotSub] = useState<string | null>(null);
  const [reverseNs, setReverseNs] = useState<string | null>(null);
  const [techModalSub, setTechModalSub] = useState<SubdomainRecord | null>(null);
  
  const shouldProcessRef = useRef(false);

  useEffect(() => {
    const saved = localStorage.getItem('domain_recon_db_v2');
    if (saved) setDomains(JSON.parse(saved));
  }, []);

  useEffect(() => {
    if(domains.length > 0) localStorage.setItem('domain_recon_db_v2', JSON.stringify(domains));
  }, [domains]);

  const updateDomainState = (updatedRecord: DomainRecord) => {
    const newDomains = [updatedRecord, ...domains.filter(d => d.id !== updatedRecord.id)];
    setDomains(newDomains);
    setSelectedDomain(updatedRecord);
  };

  const calculateStats = (subs: SubdomainRecord[]) => ({
    total: subs.length,
    expired: subs.filter(s => isExpired(s.notAfter)).length,
    wildcard: subs.filter(s => s.isWildcard).length,
    expiringSoon: subs.filter(s => isExpiringSoon(s.notAfter)).length,
    active: subs.filter(s => s.resolutionStatus === 'active').length,
    techIdentified: subs.filter(s => s.technologies && s.technologies.length > 0).length,
    lowSecurity: subs.filter(s => s.security?.grade === 'D' || s.security?.grade === 'F').length
  });

  const handleScan = async (e: any, domainOverride?: string) => {
    if(e) e.preventDefault();
    const target = (domainOverride || searchQuery).trim().toLowerCase();
    if(!target) return;
    setLoading(true);

    try {
      const [subs, ns] = await Promise.all([fetchSubdomains(target), fetchNameServers(target)]);
      const existing = domains.find(d => d.domain === target);
      const now = Date.now();
      
      const newRecord: DomainRecord = {
        id: existing?.id || crypto.randomUUID(),
        domain: target,
        nameServers: ns,
        subdomains: subs,
        createdAt: existing?.createdAt || now,
        lastScannedAt: now,
        status: 'scanned',
        stats: calculateStats(subs)
      };

      updateDomainState(newRecord);
      setSearchQuery('');
    } catch(err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleImportDomain = async (domain: string) => {
    setReverseNs(null);
    await handleScan(null, domain);
  };

  const handleDelete = (id: string, e: any) => {
    e.stopPropagation();
    if(confirm('Delete this domain?')) {
      setDomains(domains.filter(d => d.id !== id));
      if(selectedDomain?.id === id) setSelectedDomain(null);
    }
  };

  const handleExportCSV = () => {
    if (!selectedDomain) return;
    const headers = ['Subdomain', 'IP', 'Cert Status', 'Expires', 'Grade', 'Tech', 'Source'];
    const rows = selectedDomain.subdomains.map(s => [
      s.name, s.ipAddress||'-', isExpired(s.notAfter) ? 'Expired' : 'Valid', s.notAfter, s.security?.grade||'-', s.technologies?.map(t=>t.name).join(', ')||'-', s.source
    ]);
    const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    const url = URL.createObjectURL(new Blob([csvContent], { type: 'text/csv' }));
    const a = document.createElement('a'); a.href=url; a.download=`${selectedDomain.domain}_recon.csv`; a.click();
  };

  const handleProcess = async (action: 'dns' | 'tech') => {
    if(!selectedDomain) return;
    setProcessing(true);
    shouldProcessRef.current = true;
    setProgress(0);
    
    const subs = [...selectedDomain.subdomains];
    const total = subs.length;
    let checked = 0;
    const batchSize = action === 'tech' ? 3 : 5;

    for (let i = 0; i < total; i += batchSize) {
      if (!shouldProcessRef.current) break;
      const batch = subs.slice(i, i + batchSize);
      
      await Promise.all(batch.map(async (sub) => {
        if (sub.isWildcard) return;
        if (action === 'dns') {
            const res = await checkDnsResolution(sub.name);
            sub.resolutionStatus = res.active ? 'active' : 'dead';
            if (res.ip) sub.ipAddress = res.ip;
        } else if (action === 'tech') {
            if (!sub.ipAddress) {
                const dns = await checkDnsResolution(sub.name);
                if (dns.active && dns.ip) {
                    sub.ipAddress = dns.ip;
                    sub.resolutionStatus = 'active';
                } else {
                    sub.resolutionStatus = 'dead';
                    return; 
                }
            }
            if (sub.resolutionStatus === 'dead') return;

            const res = await analyzeTarget(sub.name);
            sub.technologies = res.tech;
            sub.security = res.security;
            if (res.tech.length > 0 || res.security.present.length > 0) sub.resolutionStatus = 'active';
        }
      }));

      checked += batch.length;
      setProgress(Math.round((checked / total) * 100));
      
      if (checked % 10 === 0) {
         updateDomainState({ ...selectedDomain, subdomains: subs, stats: calculateStats(subs) });
      }
    }
    updateDomainState({ ...selectedDomain, subdomains: subs, stats: calculateStats(subs) });
    setProcessing(false);
    setProgress(0);
  };

  if (selectedDomain) {
    const displayedSubdomains = selectedDomain.subdomains.filter(s => {
      // 1. Tab Filter
      if (filterType === 'live' && s.resolutionStatus !== 'active') return false;
      if (filterType === 'expired' && !isExpired(s.notAfter)) return false;
      if (filterType === 'expiring' && !isExpiringSoon(s.notAfter)) return false;
      if (filterType === 'wildcard' && !s.isWildcard) return false;

      // 2. Search Filter
      if (tableSearch) {
        const q = tableSearch.toLowerCase();
        return s.name.includes(q) || s.issuer.toLowerCase().includes(q) || s.technologies?.some(t => t.name.toLowerCase().includes(q));
      }
      return true;
    });

    return (
      <div className="min-h-screen bg-slate-900 text-slate-200 p-4 md:p-8 font-sans">
        {reverseNs && <ReverseNSModal ns={reverseNs} onClose={() => setReverseNs(null)} onImport={handleImportDomain} />}
        {screenshotSub && <ScreenshotModal subdomain={screenshotSub} onClose={() => setScreenshotSub(null)} />}
        {techModalSub && <TechProfileModal subdomain={techModalSub} onClose={() => setTechModalSub(null)} />}

        <div className="max-w-6xl mx-auto space-y-6">
          {/* HEADER */}
          <header className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="flex items-center space-x-4">
              <button onClick={() => setSelectedDomain(null)} className="p-2 hover:bg-slate-800 rounded-full text-slate-400"><ArrowLeft className="w-6 h-6" /></button>
              <div>
                <h1 className="text-2xl font-bold text-white flex items-center gap-2"><Globe className="w-6 h-6 text-blue-400" />{selectedDomain.domain}</h1>
                <div className="flex gap-2 text-xs text-slate-400 mt-1 items-center flex-wrap">
                   {selectedDomain.nameServers?.map((ns, i) => (<Badge key={i} color="slate" onClick={() => setReverseNs(ns)} className="group">{ns} <Share2 className="w-3 h-3 text-purple-400 opacity-0 group-hover:opacity-100 transition-opacity ml-1" /></Badge>))}
                </div>
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-3">
               {processing && <div className="flex items-center gap-2 text-blue-400 text-sm bg-slate-800 px-3 py-1.5 rounded-lg border border-slate-700"><Loader2 className="w-4 h-4 animate-spin"/><span>{progress}%</span><button onClick={() => shouldProcessRef.current = false} className="text-red-400"><StopCircle className="w-4 h-4"/></button></div>}
               <div className="flex bg-slate-800 rounded-lg p-1 border border-slate-700">
                  <Button variant="ghost" icon={Activity} disabled={loading || processing} onClick={() => handleProcess('dns')} className="!px-3 !py-1.5">DNS</Button>
                  <Button variant="ghost" icon={Shield} disabled={loading || processing} onClick={() => handleProcess('tech')} className="!px-3 !py-1.5">Audit</Button>
               </div>
               <Button variant="primary" icon={RefreshCw} disabled={loading || processing} onClick={() => handleScan(null, selectedDomain.domain)}>Rescan</Button>
            </div>
          </header>

          {/* STATS BAR */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
             <div className="bg-slate-800 p-3 rounded-lg border border-slate-700 flex items-center gap-3">
                <div className="p-2 bg-blue-500/10 rounded text-blue-400"><Database className="w-5 h-5"/></div>
                <div><div className="text-xl font-bold text-white">{selectedDomain.stats.total}</div><div className="text-xs text-slate-400 uppercase font-bold">Total Assets</div></div>
             </div>
             <div className="bg-slate-800 p-3 rounded-lg border border-slate-700 flex items-center gap-3">
                <div className="p-2 bg-red-500/10 rounded text-red-400"><AlertTriangle className="w-5 h-5"/></div>
                <div><div className="text-xl font-bold text-white">{selectedDomain.stats.expired}</div><div className="text-xs text-slate-400 uppercase font-bold">Expired Certs</div></div>
             </div>
             <div className="bg-slate-800 p-3 rounded-lg border border-slate-700 flex items-center gap-3">
                <div className="p-2 bg-yellow-500/10 rounded text-yellow-400"><Clock className="w-5 h-5"/></div>
                <div><div className="text-xl font-bold text-white">{selectedDomain.stats.expiringSoon}</div><div className="text-xs text-slate-400 uppercase font-bold">Expiring Soon</div></div>
             </div>
             <div className="bg-slate-800 p-3 rounded-lg border border-slate-700 flex items-center gap-3">
                <div className="p-2 bg-purple-500/10 rounded text-purple-400"><Cpu className="w-5 h-5"/></div>
                <div><div className="text-xl font-bold text-white">{selectedDomain.stats.techIdentified || 0}</div><div className="text-xs text-slate-400 uppercase font-bold">Fingerprinted</div></div>
             </div>
          </div>

          {/* MAIN CONTENT AREA */}
          <div className="bg-slate-800 border border-slate-700 rounded-xl overflow-hidden shadow-xl flex flex-col h-[700px]">
            {/* FILTERS */}
            <div className="p-4 border-b border-slate-700 bg-slate-800/50 space-y-4">
               <div className="flex flex-col md:flex-row gap-4 justify-between">
                  <div className="flex bg-slate-900 p-1 rounded-lg border border-slate-700 overflow-x-auto">
                     {['all', 'live', 'expired', 'expiring', 'wildcard'].map(f => (
                        <button 
                           key={f} 
                           onClick={() => setFilterType(f as any)}
                           className={`px-3 py-1.5 rounded-md text-sm font-medium capitalize transition-all ${filterType === f ? 'bg-blue-600 text-white shadow-lg' : 'text-slate-400 hover:text-white'}`}
                        >
                           {f}
                        </button>
                     ))}
                  </div>
                  <div className="flex items-center gap-2">
                     <div className="relative">
                        <Search className="absolute left-3 top-2 h-4 w-4 text-slate-500" />
                        <input type="text" className="bg-slate-900 border border-slate-600 rounded-md pl-9 pr-3 py-1.5 text-sm focus:outline-none focus:border-blue-500 w-48 md:w-64" placeholder="Search host, tech, issuer..." value={tableSearch} onChange={e => setTableSearch(e.target.value)} />
                     </div>
                     <div className="bg-slate-900 rounded-lg p-1 flex border border-slate-700">
                        <button onClick={() => setViewMode('list')} className={`p-1.5 rounded-md ${viewMode === 'list' ? 'bg-slate-700 text-white' : 'text-slate-500'}`}><List className="w-4 h-4" /></button>
                        <button onClick={() => setViewMode('gallery')} className={`p-1.5 rounded-md ${viewMode === 'gallery' ? 'bg-slate-700 text-white' : 'text-slate-500'}`}><LayoutGrid className="w-4 h-4" /></button>
                     </div>
                     <Button variant="ghost" icon={FileSpreadsheet} onClick={handleExportCSV} className="!px-2">CSV</Button>
                  </div>
               </div>
            </div>

            <div className="overflow-auto flex-1 bg-slate-900/50">
               {viewMode === 'list' ? (
                 <table className="w-full text-left text-sm text-slate-300">
                    <thead className="bg-slate-900/95 sticky top-0 z-10 text-slate-400 shadow-sm">
                      <tr><th className="p-4 font-medium">Subdomain</th><th className="p-4 font-medium w-32">Certificate</th><th className="p-4 font-medium w-24 text-center">Grade</th><th className="p-4 font-medium">Stack</th><th className="p-4 font-medium text-right w-32">Actions</th></tr>
                    </thead>
                    <tbody className="divide-y divide-slate-700/50">
                      {displayedSubdomains.map((sub, idx) => {
                         const daysLeft = getDaysRemaining(sub.notAfter);
                         const expired = daysLeft < 0;
                         const expiring = daysLeft > 0 && daysLeft < 30;
                         return (
                           <tr key={idx} className={`hover:bg-slate-800/50 transition-colors cursor-pointer ${expired ? 'bg-red-900/10' : ''}`} onClick={() => setTechModalSub(sub)}>
                             <td className="p-4">
                               <div className="flex flex-col">
                                  <span className="font-mono text-white select-all">{sub.name}</span>
                                  {sub.ipAddress && <span className="text-[10px] text-slate-500 font-mono mt-0.5">{sub.ipAddress}</span>}
                                  {sub.isWildcard && <span className="text-[10px] text-purple-400">*. Wildcard</span>}
                               </div>
                             </td>
                             <td className="p-4">
                                {sub.notAfter ? (
                                   expired ? <Badge color="red"><XCircle className="w-3 h-3"/> Expired</Badge> : 
                                   expiring ? <Badge color="orange"><Clock className="w-3 h-3"/> {daysLeft}d left</Badge> : 
                                   <Badge color="green"><CheckCircle2 className="w-3 h-3"/> Valid</Badge>
                                ) : <span className="text-slate-600 text-xs">-</span>}
                             </td>
                             <td className="p-4 text-center"><div className="flex justify-center"><GradeBadge grade={sub.security?.grade} /></div></td>
                             <td className="p-4"><div className="flex flex-wrap gap-1">{sub.technologies?.slice(0, 2).map((t, i) => <TechBadge key={i} tech={t} />)}{(sub.technologies?.length || 0) > 2 && <span className="text-[10px] text-slate-500">+{sub.technologies!.length - 2}</span>}</div></td>
                             <td className="p-4 text-right"><div className="flex items-center justify-end gap-2">{!sub.isWildcard && <button onClick={(e) => { e.stopPropagation(); setScreenshotSub(sub.name); }} className="text-slate-500 hover:text-blue-400 p-2"><Camera className="w-4 h-4" /></button>}<a href={`https://${sub.name}`} target="_blank" onClick={e => e.stopPropagation()} className="text-slate-500 hover:text-blue-400 p-2"><Eye className="w-4 h-4" /></a></div></td>
                           </tr>
                         );
                      })}
                    </tbody>
                 </table>
               ) : (
                 <div className="p-4 grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4">
                    {displayedSubdomains.map((sub, idx) => (!sub.isWildcard ? <div key={idx} className="h-64 cursor-pointer" onClick={() => setTechModalSub(sub)}><DomainThumbnail subdomain={sub} /></div> : null))}
                 </div>
               )}
            </div>
          </div>
        </div>
      </div>
    );
  }

  // --- DASHBOARD (HOME) ---
  return (
    <div className="min-h-screen bg-slate-900 text-slate-200 p-4 md:p-8 font-sans flex flex-col items-center">
      <div className="w-full max-w-4xl space-y-8">
        <div className="text-center space-y-2">
          <div className="inline-flex p-4 bg-blue-500/10 rounded-2xl mb-2"><Network className="w-12 h-12 text-blue-400"/></div>
          <h1 className="text-4xl font-bold text-white">Domain Recon <span className="text-blue-500">V2</span></h1>
          <p className="text-slate-400">Serverless EASM. Hosted on GitHub.</p>
        </div>
        <form onSubmit={handleScan} className="flex gap-2 relative z-10">
          <input type="text" className="w-full bg-slate-800 border border-slate-700 rounded-xl px-6 py-4 text-lg focus:outline-none focus:ring-2 focus:ring-blue-500 transition-all" placeholder="Enter root domain (e.g. google.com)" value={searchQuery} onChange={e => setSearchQuery(e.target.value)} />
          <button disabled={loading || !searchQuery} className="bg-blue-600 hover:bg-blue-500 text-white px-8 rounded-xl font-bold transition-all disabled:opacity-50">{loading ? <Loader2 className="animate-spin"/> : 'Scan'}</button>
        </form>
        <div className="grid gap-3">
          {domains.map(d => (
            <div key={d.id} onClick={() => setSelectedDomain(d)} className="bg-slate-800 p-4 rounded-xl border border-slate-700 hover:border-blue-500/50 cursor-pointer flex justify-between items-center group transition-all">
              <div className="flex items-center gap-4">
                <div className="h-12 w-12 bg-slate-900 rounded-full flex items-center justify-center font-bold text-xl text-blue-500">{d.domain[0].toUpperCase()}</div>
                <div><h3 className="font-bold text-white text-lg">{d.domain}</h3><div className="text-sm text-slate-500">{d.subdomains.length} assets • {d.stats.active||0} active</div></div>
              </div>
              <button onClick={(e) => handleDelete(d.id, e)} className="p-2 text-slate-600 hover:text-red-400 opacity-0 group-hover:opacity-100 transition-all"><Trash2/></button>
            </div>
          ))}
          {domains.length === 0 && !loading && (
            <div className="text-center py-20 border-2 border-dashed border-slate-800 rounded-xl text-slate-600"><Database className="w-12 h-12 mx-auto mb-4 opacity-20"/><p>No domains tracked.</p><p className="text-sm">Data is saved to your browser.</p></div>
          )}
        </div>
      </div>
    </div>
  );
}