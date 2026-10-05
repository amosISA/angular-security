import { Routes } from '@angular/router';

export const routes: Routes = [
  {
    path: '',
    pathMatch: 'full',
    loadComponent: () => import('./home').then((m) => m.Home),
    title: 'Angular security demos',
  },
  {
    path: 'sanitizer',
    loadComponent: () => import('./vulns/sanitizer-works').then((m) => m.SanitizerWorks),
    title: 'What Angular blocks',
  },
  {
    path: 'xss-bypass',
    loadComponent: () => import('./vulns/xss-bypass').then((m) => m.XssBypass),
    title: 'bypassSecurityTrustHtml',
  },
  {
    path: 'dom-injection',
    loadComponent: () => import('./vulns/dom-injection').then((m) => m.DomInjection),
    title: 'Direct DOM access',
  },
  {
    path: 'guard-bypass',
    loadComponent: () => import('./vulns/guard-bypass').then((m) => m.GuardBypass),
    title: 'Guards are not authorisation',
  },
  {
    path: 'transfer-cache',
    loadComponent: () => import('./vulns/transfer-cache').then((m) => m.TransferCache),
    title: 'SSR transfer cache',
  },
  {
    path: 'hash-collision',
    loadComponent: () => import('./vulns/hash-collision').then((m) => m.HashCollision),
    title: '32-bit cache keys',
  },
  {
    path: 'dom-clobbering',
    loadComponent: () => import('./vulns/dom-clobbering').then((m) => m.DomClobbering),
    title: 'DOM clobbering',
  },
  {
    path: 'supply-chain',
    loadComponent: () => import('./vulns/supply-chain').then((m) => m.SupplyChain),
    title: 'npm supply chain',
  },
  {
    path: 'defences',
    loadComponent: () => import('./vulns/defences').then((m) => m.Defences),
    title: 'Defences',
  },
  { path: '**', redirectTo: '' },
];
