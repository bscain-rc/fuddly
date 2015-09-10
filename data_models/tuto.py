from fuzzfmk.data_model import *
from fuzzfmk.value_types import *
from fuzzfmk.data_model_helpers import *

class MyDF_DataModel(DataModel):

    file_extension = 'df'
    name = 'mydf'

    def dissect(self, data, idx):
        pass

    def build_data_model(self):

        test_node_desc = \
        {'name': 'TestNode',
         'contents': [
             # block 1
             {'section_type': MH.Ordered,
              'duplicate_mode': MH.Copy,
              'contents': [
                  
                  {'contents': BitField(subfield_sizes=[21,2,1], endian=VT.BigEndian,
                                        subfield_val_lists=[None, [0b10], [0,1]],
                                        subfield_val_extremums=[[500, 600], None, None]),
                   'name': 'val1',
                   'qty': (1, 5)},
                  
                  {'name': 'val2'},
                  
                  {'name': 'middle',
                   'mode': MH.NotMutableClone,
                   'contents': [{
                       'section_type': MH.Random,
                       'contents': [
                           
                           {'contents': String(val_list=['OK', 'KO'], size=2),
                            'name': 'val2',
                            'qty': (1, 3)},
                           
                           {'name': 'val21',
                            'clone': 'val1'},
                           
                           {'name': 'USB_desc',
                            'export_from': 'usb',
                            'data_id': 'STR'},
                           
                           {'type': MH.Generator,
                            'contents': lambda x: Node('cts', values=[x[0].to_bytes() \
                                                                      + x[1].to_bytes()]),
                            'name': 'val22',
                            'node_args': [('val21', 2), 'val3']}
                       ]}]},
                  
                  {'contents': String(max_sz = 10),
                   'name': 'val3',
                   'sync_qty_with': 'val1',
                   'alt': [
                       {'conf': 'alt1',
                        'contents': SINT8(int_list=[1,4,8])},
                       {'conf': 'alt2',
                        'contents': UINT16_be(mini=0xeeee, maxi=0xff56),
                        'determinist': True}]}
              ]},
             
             # block 2
             {'section_type': MH.Pick,
              'weights': (10,5),
              'contents': [
                  {'contents': String(val_list=['PLIP', 'PLOP'], size=4),
                   'name': 'val4'},
                  
                  {'contents': SINT16_be(int_list=[-1, -3, -5, 7]),
                   'name': 'val5'}
              ]},
            
             # block 3
             {'section_type': MH.FullyRandom,
              'contents': [
                  {'contents': String(val_list=['AAA', 'BBBB', 'CCCCC']),
                   'name': ('val21', 2)},
                  
                  {'contents': UINT8(int_list=[2, 4, 6, 8]),
                   'qty': (2, 3),
                   'name': ('val22', 2)}
              ]}
         ]}


        def keycode_helper(blob, constraints, node_internals):
            off = blob.find(b'\xd2')
            if off > -1:
                return AbsorbStatus.Accept, off, None
            else:
                return AbsorbStatus.Reject, 0, None

        abstest_desc = \
        {'name': 'AbsTest',
         'contents': [

             {'name': 'prefix',
              'contents': UINT8(int_list=[0xcc, 0xff, 0xee])},

             {'name': 'variable_string',
              'contents': String(max_sz=20),
              'set_attrs': [NodeInternals.Abs_Postpone]},

             {'name': 'keycode',
              'contents': UINT16_be(int_list=[0xd2d3, 0xd2fe, 0xd2aa]),
              'absorb_helper': keycode_helper},

             {'name': 'variable_suffix',
              'contents': String(val_list=['END', 'THE_END'])}
         ]}


        abstest2_desc = \
        {'name': 'AbsTest2',
         'contents': [

             {'name': 'prefix',
              'contents': UINT8(int_list=[0xcc, 0xff, 0xee])},

             {'name': 'variable_string',
              'contents': String(max_sz=20),
              'set_attrs': [NodeInternals.Abs_Postpone]},

             {'name': 'keycode',
              'contents': UINT16_be(int_list=[0xd2d3, 0xd2fe, 0xd2aa])},

             {'name': 'variable_suffix',
              'contents': String(val_list=['END', 'THE_END'])}
         ]}


        self.register(test_node_desc, abstest_desc, abstest2_desc)



data_model = MyDF_DataModel()
