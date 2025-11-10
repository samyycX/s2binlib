
import json
from typing import List, Dict, Tuple, Set
from collections import defaultdict

# 示例数据（部分）
vtable_data = json.load(open("dump/windows/vtables/server.txt"))

class VTableComparator:
    """虚表对比器"""
    
    def __init__(self, vtable_data: List[Dict]):
        self.vtable_data = vtable_data
        self.vtable_dict = {vt['type_name']: vt for vt in vtable_data}
    
    def get_available_classes(self) -> List[str]:
        """获取所有可用的类名"""
        return list(self.vtable_dict.keys())
    
    def compare_vtables(self, class1: str, class2: str) -> Dict:
        """对比两个虚表"""
        if class1 not in self.vtable_dict:
            raise ValueError(f"类 '{class1}' 不存在")
        if class2 not in self.vtable_dict:
            raise ValueError(f"类 '{class2}' 不存在")
        
        vt1 = self.vtable_dict[class1]
        vt2 = self.vtable_dict[class2]
        
        methods1 = vt1['methods']
        methods2 = vt2['methods']
        
        # 转换为集合以便比较
        set1 = set(methods1)
        set2 = set(methods2)
        
        # 找出相同和不同的方法
        common_methods = set1 & set2
        only_in_class1 = set1 - set2
        only_in_class2 = set2 - set1
        
        # 按索引对比（考虑虚函数表的顺序）
        indexed_comparison = []
        max_len = max(len(methods1), len(methods2))
        
        for i in range(max_len):
            entry = {'index': i}
            
            if i < len(methods1):
                entry['class1_method'] = methods1[i]
            else:
                entry['class1_method'] = None
            
            if i < len(methods2):
                entry['class2_method'] = methods2[i]
            else:
                entry['class2_method'] = None
            
            # 判断是否相同
            if entry['class1_method'] and entry['class2_method']:
                entry['match'] = entry['class1_method'] == entry['class2_method']
            else:
                entry['match'] = False
            
            indexed_comparison.append(entry)
        
        return {
            'class1': {
                'name': class1,
                'vtable_address': hex(vt1['vtable_address']),
                'method_count': len(methods1),
                'methods': methods1
            },
            'class2': {
                'name': class2,
                'vtable_address': hex(vt2['vtable_address']),
                'method_count': len(methods2),
                'methods': methods2
            },
            'comparison': {
                'common_methods': sorted(list(common_methods)),
                'common_count': len(common_methods),
                'only_in_class1': sorted(list(only_in_class1)),
                'only_in_class1_count': len(only_in_class1),
                'only_in_class2': sorted(list(only_in_class2)),
                'only_in_class2_count': len(only_in_class2),
                'indexed_comparison': indexed_comparison
            }
        }
    
    def print_comparison(self, class1: str, class2: str):
        """打印美观的对比结果"""
        result = self.compare_vtables(class1, class2)
        
        # 打印标题
        print("=" * 100)
        print(f"{'虚表对比分析':^100}")
        print("=" * 100)
        print()
        
        # 打印类信息
        print(f"📋 类 1: {result['class1']['name']}")
        print(f"   ├─ 虚表地址: {result['class1']['vtable_address']}")
        print(f"   └─ 虚函数数量: {result['class1']['method_count']}")
        print()
        
        print(f"📋 类 2: {result['class2']['name']}")
        print(f"   ├─ 虚表地址: {result['class2']['vtable_address']}")
        print(f"   └─ 虚函数数量: {result['class2']['method_count']}")
        print()
        
        # 打印统计信息
        print("=" * 100)
        print(f"{'统计摘要':^100}")
        print("=" * 100)
        comp = result['comparison']
        
        print(f"\n✅ 相同的虚函数: {comp['common_count']} 个")
        print(f"❌ 仅在 {result['class1']['name']} 中: {comp['only_in_class1_count']} 个")
        print(f"❌ 仅在 {result['class2']['name']} 中: {comp['only_in_class2_count']} 个")
        print()
        
        # 打印详细对比表
        print("=" * 100)
        print(f"{'按索引详细对比':^100}")
        print("=" * 100)
        print(f"\n{'索引':<8} {'类 1 方法地址':<20} {'类 2 方法地址':<20} {'状态':<15}")
        print("-" * 100)
        
        for entry in comp['indexed_comparison']:
            idx = entry['index']
            m1 = hex(entry['class1_method']) if entry['class1_method'] else "---"
            m2 = hex(entry['class2_method']) if entry['class2_method'] else "---"
            
            if entry['match']:
                status = "✅ 相同"
            elif entry['class1_method'] is None:
                status = "➕ 类2独有"
            elif entry['class2_method'] is None:
                status = "➖ 类1独有"
            else:
                status = "❌ 不同"
            
            print(f"{idx:<8} {m1:<20} {m2:<20} {status:<15}")
        
        # 打印相同方法列表
        if comp['common_methods']:
            print("\n" + "=" * 100)
            print(f"{'相同的虚函数地址':^100}")
            print("=" * 100)
            for i, method in enumerate(comp['common_methods'], 1):
                print(f"  {i:2d}. {hex(method)}")
        
        # 打印差异方法
        if comp['only_in_class1']:
            print("\n" + "=" * 100)
            print(f"仅在 {result['class1']['name']} 中的虚函数".center(100))
            print("=" * 100)
            for i, method in enumerate(comp['only_in_class1'], 1):
                print(f"  {i:2d}. {hex(method)}")
        
        if comp['only_in_class2']:
            print("\n" + "=" * 100)
            print(f"仅在 {result['class2']['name']} 中的虚函数".center(100))
            print("=" * 100)
            for i, method in enumerate(comp['only_in_class2'], 1):
                print(f"  {i:2d}. {hex(method)}")
        
        print("\n" + "=" * 100)
        print()

# 创建对比器实例
comparator = VTableComparator(vtable_data)

# 显示可用的类
# print("可用的类列表：")
# print("-" * 50)
# for i, class_name in enumerate(comparator.get_available_classes(), 1):
#     print(f"{i:2d}. {class_name}")
# print("\n")

# 示例：对比两个类
# print("示例 1: 对比 BotBombStatusMeme 和 BotBombsiteStatusMeme")
# print()
comparator.print_comparison("CBaseEntity", "CFuncTrackTrain")
