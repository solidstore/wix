// Copyright (c) .NET Foundation and contributors. All rights reserved. Licensed under the Microsoft Reciprocal License. See LICENSE.TXT file in the project root for full license information.

namespace WixToolset.Http
{
    using WixToolset.Data;
    using WixToolset.Http.Symbols;

    public static partial class HttpSymbolDefinitions
    {
        public static readonly IntermediateSymbolDefinition WixHttpSslCert = new IntermediateSymbolDefinition(
            HttpSymbolDefinitionType.WixHttpSslCert.ToString(),
            new[]
            {
                new IntermediateFieldDefinition(nameof(WixHttpSslCertSymbolFields.Host), IntermediateFieldType.String),
                new IntermediateFieldDefinition(nameof(WixHttpSslCertSymbolFields.Port), IntermediateFieldType.String),
                new IntermediateFieldDefinition(nameof(WixHttpSslCertSymbolFields.Thumbprint), IntermediateFieldType.String),
                new IntermediateFieldDefinition(nameof(WixHttpSslCertSymbolFields.CertificateRef), IntermediateFieldType.String),
                new IntermediateFieldDefinition(nameof(WixHttpSslCertSymbolFields.AppId), IntermediateFieldType.String),
                new IntermediateFieldDefinition(nameof(WixHttpSslCertSymbolFields.Store), IntermediateFieldType.String),
                new IntermediateFieldDefinition(nameof(WixHttpSslCertSymbolFields.HandleExisting), IntermediateFieldType.Number),
                new IntermediateFieldDefinition(nameof(WixHttpSslCertSymbolFields.ComponentRef), IntermediateFieldType.String),
            },
            typeof(WixHttpSslCertSymbol));
    }
}

namespace WixToolset.Http.Symbols
{
    using WixToolset.Data;

    public enum WixHttpSslCertSymbolFields
    {
        Host,
        Port,
        Thumbprint,
        CertificateRef,
        AppId,
        Store,
        HandleExisting,
        ComponentRef,
    }

    public class WixHttpSslCertSymbol : IntermediateSymbol
    {
        public WixHttpSslCertSymbol() : base(HttpSymbolDefinitions.WixHttpSslCert, null, null)
        {
        }

        public WixHttpSslCertSymbol(SourceLineNumber sourceLineNumber, Identifier id = null) : base(HttpSymbolDefinitions.WixHttpSslCert, sourceLineNumber, id)
        {
        }

        public IntermediateField this[WixHttpSslCertSymbolFields index] => this.Fields[(int)index];

        public string Host
        {
            get => this.Fields[(int)WixHttpSslCertSymbolFields.Host].AsString();
            set => this.Set((int)WixHttpSslCertSymbolFields.Host, value);
        }

        public string Port
        {
            get => this.Fields[(int)WixHttpSslCertSymbolFields.Port].AsString();
            set => this.Set((int)WixHttpSslCertSymbolFields.Port, value);
        }

        public string Thumbprint
        {
            get => this.Fields[(int)WixHttpSslCertSymbolFields.Thumbprint].AsString();
            set => this.Set((int)WixHttpSslCertSymbolFields.Thumbprint, value);
        }

        public string CertificateRef
        {
            get => this.Fields[(int)WixHttpSslCertSymbolFields.CertificateRef].AsString();
            set => this.Set((int)WixHttpSslCertSymbolFields.CertificateRef, value);
        }

        public string AppId
        {
            get => this.Fields[(int)WixHttpSslCertSymbolFields.AppId].AsString();
            set => this.Set((int)WixHttpSslCertSymbolFields.AppId, value);
        }

        public string Store
        {
            get => this.Fields[(int)WixHttpSslCertSymbolFields.Store].AsString();
            set => this.Set((int)WixHttpSslCertSymbolFields.Store, value);
        }

        public HandleExisting HandleExisting
        {
            get => (HandleExisting)this.Fields[(int)WixHttpSslCertSymbolFields.HandleExisting].AsNumber();
            set => this.Set((int)WixHttpSslCertSymbolFields.HandleExisting, (int)value);
        }

        public string ComponentRef
        {
            get => this.Fields[(int)WixHttpSslCertSymbolFields.ComponentRef].AsString();
            set => this.Set((int)WixHttpSslCertSymbolFields.ComponentRef, value);
        }
    }
}
