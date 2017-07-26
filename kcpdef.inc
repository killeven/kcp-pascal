//  判断当前编译器版本(Delphi7以上版本支持uint64类型)
//Delphi 8
{$ifdef VER160}
  {$define D7UP}
{$endif}
// Delphi 2005
{$ifdef VER170}
  {$define D7UP}
{$endif}
// Delphi 2006
{$ifdef VER180}
  {$define D7UP}
{$endif}
// Delphi 2007 Rad studio
{$ifdef VER185}
  {$define D7UP}
{$endif}
// Delphi 2007 - NET
{$ifdef VER190}
  {$define D7UP}
{$endif}
// Delphi 2009(Delphi2009开始编译器默认采用Unicode类型)
{$ifdef VER200}
  {$define D7UP}
  {$define D12UP}
{$endif}
// Delphi 2010
{$ifdef VER210}
  {$define D7UP}
  {$define D12UP}
{$endif}
// Delphi XE
{$ifdef VER220}
  {$define D7UP}
  {$define D12UP}
  {$define DXEUP}
{$endif}
// Delphi XE2(开始支持64位)
{$ifdef VER230}
  {$define  D7UP}
  {$define  D12UP}
  {$define  D15UP}
  {$define  DXE2UP}
{$endif}