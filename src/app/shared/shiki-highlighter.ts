import bash from '@shikijs/langs/bash';
import html from '@shikijs/langs/html';
import http from '@shikijs/langs/http';
import json from '@shikijs/langs/json';
import jsonc from '@shikijs/langs/jsonc';
import typescript from '@shikijs/langs/typescript';
import yaml from '@shikijs/langs/yaml';
import darkPlus from '@shikijs/themes/dark-plus';
import { createHighlighterCore } from 'shiki/core';
import { createJavaScriptRegexEngine } from 'shiki/engine/javascript';

export type CodeLanguage = 'bash' | 'html' | 'http' | 'json' | 'jsonc' | 'typescript' | 'yaml';

export interface HighlightedCode {
  readonly background: string;
  readonly foreground: string;
  readonly lines: readonly (readonly { readonly color: string; readonly content: string }[])[];
}

const themeName = 'dark-plus';
const highlighter = createHighlighterCore({
  engine: createJavaScriptRegexEngine(),
  langs: [bash, html, http, json, jsonc, typescript, yaml],
  themes: [darkPlus],
});

export async function highlightCode(
  code: string,
  language: CodeLanguage,
): Promise<HighlightedCode> {
  const instance = await highlighter;
  const result = instance.codeToTokens(code, {
    lang: language,
    theme: themeName,
  });
  const background = result.bg ?? '#1e1e1e';
  const foreground = result.fg ?? '#d4d4d4';

  return {
    background,
    foreground,
    lines: result.tokens.map((line) =>
      line.map((token) => ({
        color: token.color ?? foreground,
        content: token.content,
      })),
    ),
  };
}
