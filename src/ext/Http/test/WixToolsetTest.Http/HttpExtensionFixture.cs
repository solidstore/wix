// Copyright (c) .NET Foundation and contributors. All rights reserved. Licensed under the Microsoft Reciprocal License. See LICENSE.TXT file in the project root for full license information.

namespace WixToolsetTest.Http
{
    using WixInternal.TestSupport;
    using WixInternal.Core.TestPackage;
    using WixToolset.Http;
    using Xunit;

    public class HttpExtensionFixture
    {
        [Fact]
        public void CanBuildUsingSniSssl()
        {
            var folder = TestData.Get("TestData", "SniSsl");
            var build = new Builder(folder, typeof(HttpExtensionFactory), new[] { folder });

            var results = build.BuildAndQuery(Build, "CustomAction", "Wix4HttpSniSslCert");
            WixAssert.CompareLineByLine(new[]
            {
                "CustomAction:Wix4ExecHttpSniSslCertsInstall_X86\t3073\tWix4HttpCA_X86\tExecHttpSniSslCerts\t",
                "CustomAction:Wix4ExecHttpSniSslCertsUninstall_X86\t3073\tWix4HttpCA_X86\tExecHttpSniSslCerts\t",
                "CustomAction:Wix4RollbackHttpSniSslCertsInstall_X86\t3329\tWix4HttpCA_X86\tExecHttpSniSslCerts\t",
                "CustomAction:Wix4RollbackHttpSniSslCertsUninstall_X86\t3329\tWix4HttpCA_X86\tExecHttpSniSslCerts\t",
                "CustomAction:Wix4SchedHttpSniSslCertsInstall_X86\t1\tWix4HttpCA_X86\tSchedHttpSniSslCertsInstall\t",
                "CustomAction:Wix4SchedHttpSniSslCertsUninstall_X86\t1\tWix4HttpCA_X86\tSchedHttpSniSslCertsUninstall\t",
                "Wix4HttpSniSslCert:sslC9YX6_H7UL_WGBx4DoDGI.Sj.D0\texample.com\t8080\t[SOME_THUMBPRINT]\t\t\t2\tfilF5_pLhBuF5b4N9XEo52g_hUM5Lo",
            }, results);
        }

        [Fact]
        public void CanBuildUsingSsl()
        {
            var folder = TestData.Get("TestData", "Ssl");
            var build = new Builder(folder, typeof(HttpExtensionFactory), new[] { folder });

            var results = build.BuildAndQuery(Build, "CustomAction", "Wix4HttpSslCert");
            WixAssert.CompareLineByLine(new[]
            {
                "CustomAction:Wix4ExecHttpSslCertsInstall_X86\t11265\tWix4HttpCA_X86\tExecHttpSslCerts\t",
                "CustomAction:Wix4ExecHttpSslCertsUninstall_X86\t11265\tWix4HttpCA_X86\tExecHttpSslCerts\t",
                "CustomAction:Wix4RollbackHttpSslCertsInstall_X86\t11521\tWix4HttpCA_X86\tExecHttpSslCerts\t",
                "CustomAction:Wix4RollbackHttpSslCertsUninstall_X86\t11521\tWix4HttpCA_X86\tExecHttpSslCerts\t",
                "CustomAction:Wix4SchedHttpSslCertsInstall_X86\t8193\tWix4HttpCA_X86\tSchedHttpSslCertsInstall\t",
                "CustomAction:Wix4SchedHttpSslCertsUninstall_X86\t8193\tWix4HttpCA_X86\tSchedHttpSslCertsUninstall\t",
                "Wix4HttpSslCert:ssle0Wgg93FXwXdLjwZWqv0HKBhhKE\t0.0.0.0\t8080\t[SOME_THUMBPRINT]\t\t\t\t2\tfilF5_pLhBuF5b4N9XEo52g_hUM5Lo",
                "Wix4HttpSslCert:ssltjEpdUFkxO7rNF2TrXuGLJg5NwE\t0.0.0.0\t8081\t\t1234\t\t\t2\tfilF5_pLhBuF5b4N9XEo52g_hUM5Lo",
            }, results);
        }

        [Fact]
        public void CanBuildUsingUrlReservation()
        {
            var folder = TestData.Get(@"TestData\UsingUrlReservation");
            var build = new Builder(folder, typeof(HttpExtensionFactory), new[] { folder });

            var results = build.BuildAndQuery(Build, "CustomAction", "Wix4HttpUrlAce", "Wix4HttpUrlReservation");
            WixAssert.CompareLineByLine(new[]
            {
                "CustomAction:Wix4ExecHttpUrlReservationsInstall_X86\t3073\tWix4HttpCA_X86\tExecHttpUrlReservations\t",
                "CustomAction:Wix4ExecHttpUrlReservationsUninstall_X86\t3073\tWix4HttpCA_X86\tExecHttpUrlReservations\t",
                "CustomAction:Wix4RollbackHttpUrlReservationsInstall_X86\t3329\tWix4HttpCA_X86\tExecHttpUrlReservations\t",
                "CustomAction:Wix4RollbackHttpUrlReservationsUninstall_X86\t3329\tWix4HttpCA_X86\tExecHttpUrlReservations\t",
                "CustomAction:Wix4SchedHttpUrlReservationsInstall_X86\t1\tWix4HttpCA_X86\tSchedHttpUrlReservationsInstall\t",
                "CustomAction:Wix4SchedHttpUrlReservationsUninstall_X86\t1\tWix4HttpCA_X86\tSchedHttpUrlReservationsUninstall\t",
                "Wix4HttpUrlAce:aceu5os2gQoblRmzwjt85LQf997uD4\turlO23FkY2xzEY54lY6E6sXFW6glXc\tNT SERVICE\\TestService\t268435456",
                "Wix4HttpUrlReservation:urlO23FkY2xzEY54lY6E6sXFW6glXc\t0\t\thttp://+:80/vroot/\tfilF5_pLhBuF5b4N9XEo52g_hUM5Lo",
            }, results);
        }

        private static void Build(string[] args)
        {
            var result = WixRunner.Execute(args)
                                  .AssertSuccess();
        }
    }
}
